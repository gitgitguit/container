/**
 * security/management-key-functions.js
 *
 * AES-256-GCM request encryption key management for server.js flow.
 * - Secure key generation (32 bytes / 256 bits)
 * - Atomic file writes & permission checks
 * - Key history management with max retention
 * - Rotation scheduler and forced rotation API
 * - Metrics collection with overflow protection and periodic persistence
 *
 * NOTE: Hardened for multi-process usage with a simple filesystem lock and
 * graceful timer management. This file intentionally keeps synchronous IO
 * operations for simplicity and deterministic atomic writes on POSIX.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

// Config: allow environment overrides (matches REQUEST-ENCRYPTION-KEY-MANAGEMENT-FUNCTIONS.md)
const DEFAULT_ENCRYPTION_KEY_DIR = process.env.ENCRYPTION_KEY_DIR || (process.env.HOME ? path.join(process.env.HOME, '.proxy-encryption') : path.join(__dirname, '..', '.proxy-encryption'));
const DEFAULT_ENCRYPTION_AUDIT_DIR = process.env.ENCRYPTION_AUDIT_DIR || (process.env.HOME ? path.join(process.env.HOME, '.proxy-audit') : path.join(__dirname, '..', '.proxy-audit'));
const DEFAULT_ENCRYPTION_CONFIG_PATH = process.env.ENCRYPTION_CONFIG_PATH || path.join(__dirname, 'attack-detection-config.json'); // fallback sensible default

// Internal defaults; may be overridden by init()
let config = {
    encryption: { enabled: false },
    keys: {
        rotationEnabled: true,
        rotationIntervalDays: 30,
        maxKeysRetained: 5
    },
    encryption_storage: {
        currentKeyFile: path.join(DEFAULT_ENCRYPTION_KEY_DIR, 'encryption-key.json'),
        keyHistoryFile: path.join(DEFAULT_ENCRYPTION_KEY_DIR, 'key-history.json')
    },
    audit: {
        auditDir: DEFAULT_ENCRYPTION_AUDIT_DIR
    },
    metricsPersistIntervalMs: 5 * 60 * 1000
};

// Internal state
const MAX_SAFE_METRIC = 2147483647;
const METRICS_ARCHIVE_THRESHOLD = MAX_SAFE_METRIC * 0.9; // 90% of max
const state = {
    currentKey: null,            // Buffer
    currentVersion: null,        // number
    keyHistory: { keys: [] },    // { keys: [ { version, key (base64), created, active, description } ] }
    metrics: {
        requestsEncrypted: 0,
        requestsDecrypted: 0,
        decryptionFailures: 0,
        keyRotations: 0
    },
    metricsArchive: [],          // Array of archived metric snapshots
    lastMetricsPersist: Date.now(),
    rotationTimer: null,
    metricsTimer: null,
    initialized: false           // Track initialization state
};

// Simple filesystem lock implementation to coordinate between processes
function _lockPathFor(name) {
    // choose lock dir near the key files so it's shared between processes using same config
    const dir = path.dirname(config && config.encryption_storage && config.encryption_storage.currentKeyFile ? config.encryption_storage.currentKeyFile : DEFAULT_ENCRYPTION_KEY_DIR);
    return path.join(dir, `.lock-${name}.lck`);
}

function _acquireLock(name, timeoutMs = 5000) {
    const lockPath = _lockPathFor(name);
    const start = Date.now();
    while (true) {
        try {
            const fd = fs.openSync(lockPath, 'wx', 0o600); // create exclusively
            fs.writeSync(fd, `${process.pid}\n${Date.now()}\n`);
            fs.closeSync(fd);
            return true;
        } catch (e) {
            // If file exists, check age and possibly remove stale lock
            try {
                const st = fs.statSync(lockPath);
                const age = Date.now() - st.mtimeMs;
                if (age > Math.max(30000, timeoutMs)) {
                    // stale lock, remove it
                    try { fs.unlinkSync(lockPath); } catch (_) {}
                    continue; // retry immediately
                }
            } catch (_) {}
            if (Date.now() - start > timeoutMs) return false;
            // sleep briefly
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
        }
    }
}

function _releaseLock(name) {
    const lockPath = _lockPathFor(name);
    try { fs.unlinkSync(lockPath); } catch (e) { /* ignore */ }
}

function _withLock(name, fn, timeoutMs = 5000) {
    if (!_acquireLock(name, timeoutMs)) throw new Error(`Failed to acquire lock: ${name}`);
    try {
        return fn();
    } finally {
        _releaseLock(name);
    }
}

// Helper utilities

/**
 * Ensure directory exists with strict permissions (0o700)
 * Enforce perms immediately.
 */
function _ensureDir(dirPath) {
    try {
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
        }
        try {
            fs.chmodSync(dirPath, 0o700);
        } catch (e) {
            console.warn('[KEY-MGR] Could not enforce directory permissions for', dirPath, e.message);
        }
    } catch (e) {
        throw new Error(`Failed to ensure directory ${dirPath}: ${e.message}`);
    }
}

/**
 * Atomic file write with proper cleanup on failure
 */
function _atomicWriteFile(filePath, data, mode = 0o600) {
    const dir = path.dirname(filePath);
    _ensureDir(dir);
    const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;

    try {
        fs.writeFileSync(tmp, data, { mode });
        fs.chmodSync(tmp, mode);  // Ensure permissions before rename
        fs.renameSync(tmp, filePath); // atomic on most unix filesystems
    } catch (e) {
        try { fs.unlinkSync(tmp); } catch (_) {}
        throw e;
    }
}

/**
 * Safe JSON file read with error handling
 */
function _readJsonFileSafe(filePath) {
    try {
        if (!fs.existsSync(filePath)) return null;
        const raw = fs.readFileSync(filePath, 'utf8');
        if (!raw || !raw.trim()) return null;
        return JSON.parse(raw);
    } catch (e) {
        console.error('[KEY-MGR] Failed to read/parse JSON file', filePath, e.message);
        return null;
    }
}

/**
 * Validate key entry structure and decrypt to verify length
 */
function _validateKeyEntry(entry) {
    if (!entry || typeof entry !== 'object') return false;
    if (!Number.isInteger(entry.version)) return false;
    if (!entry.key || typeof entry.key !== 'string') return false;
    try {
        const buf = Buffer.from(entry.key, 'base64');
        if (buf.length !== 32) return false;
    } catch (e) {
        return false;
    }
    return true;
}

/**
 * Generate random AES-256 key (32 bytes) base64
 */
function _generateKeyBase64() {
    const buf = crypto.randomBytes(32); // AES-256 key
    return buf.toString('base64');
}

/**
 * Increment metric with overflow protection
 */
function _incrementMetric(name) {
    if (!(name in state.metrics)) return;

    if (state.metrics[name] >= METRICS_ARCHIVE_THRESHOLD) {
        console.warn('[KEY-MGR] ⚠️  Metric overflow warning for', name, `(${state.metrics[name]} / ${MAX_SAFE_METRIC})`);
        _archiveMetrics(`overflow-${name}-at-${Date.now()}`);
        state.metrics[name] = 1;
    } else {
        state.metrics[name]++;
    }
}

/**
 * Archive current metrics snapshot to audit trail
 */
function _archiveMetrics(reason = 'periodic') {
    try {
        const snapshot = {
            reason,
            metrics: { ...state.metrics },
            timestamp: new Date().toISOString(),
            archivedCount: state.metricsArchive.length + 1
        };
        state.metricsArchive.push(snapshot);
        if (state.metricsArchive.length > 10) state.metricsArchive.shift();
        logEvent('metrics_archived', { reason, metrics: snapshot.metrics });
    } catch (e) {
        console.warn('[KEY-MGR] Failed to archive metrics:', e.message);
    }
}

/**
 * Persist metrics to disk
 */
function _persistMetrics() {
    try {
        const auditDir = config.audit.auditDir;
        _ensureDir(auditDir);
        const metricsFile = path.join(auditDir, 'encryption-metrics.json');
        const payload = {
            metrics: state.metrics,
            archive: state.metricsArchive,
            timestamp: new Date().toISOString()
        };
        _atomicWriteFile(metricsFile, JSON.stringify(payload, null, 2));
        state.lastMetricsPersist = Date.now();
    } catch (e) {
        console.error('[KEY-MGR] Failed to persist metrics:', e.message);
    }
}

/**
 * Save current active key to file (tolerant)
 */
function _saveCurrentKeyFile() {
    const filePath = config.encryption_storage.currentKeyFile;
    if (!filePath) throw new Error('currentKeyFile not configured');
    const active = state.keyHistory.keys.find(k => k.version === state.currentVersion && k.active);
    if (!active) {
        // No active key to persist; if we have an in-memory currentKey, persist minimal metadata
        if (state.currentKey && state.currentVersion) {
            const payload = {
                version: state.currentVersion,
                key: state.currentKey.toString('base64'),
                created: new Date().toISOString(),
                active: true,
                description: 'auto-persisted'
            };
            _atomicWriteFile(filePath, JSON.stringify(payload, null, 2), 0o600);
            return;
        }
        throw new Error('No active key in history to persist');
    }
    const payload = {
        version: active.version,
        key: active.key,
        created: active.created,
        active: !!active.active,
        description: active.description || ''
    };
    _atomicWriteFile(filePath, JSON.stringify(payload, null, 2), 0o600);
}

/**
 * Save key history to file
 */
function _saveKeyHistory() {
    const filePath = config.encryption_storage.keyHistoryFile;
    if (!filePath) throw new Error('keyHistoryFile not configured');
    const payload = { keys: state.keyHistory.keys };
    _atomicWriteFile(filePath, JSON.stringify(payload, null, 2), 0o600);
}

/**
 * Load keys from disk
 */
function _loadKeyFiles() {
    const historyPath = config.encryption_storage.keyHistoryFile;
    const currentPath = config.encryption_storage.currentKeyFile;

    const history = _readJsonFileSafe(historyPath);
    if (history && Array.isArray(history.keys)) {
        state.keyHistory.keys = history.keys.filter(_validateKeyEntry).map(e => ({
            version: e.version,
            key: e.key,
            created: e.created || new Date().toISOString(),
            active: !!e.active,
            description: e.description || ''
        }));
    } else {
        state.keyHistory.keys = [];
    }

    const current = _readJsonFileSafe(currentPath);
    if (current && _validateKeyEntry(current)) {
        const found = state.keyHistory.keys.find(k => k.version === current.version);
        if (!found) {
            state.keyHistory.keys.push({
                version: current.version,
                key: current.key,
                created: current.created || new Date().toISOString(),
                active: !!current.active,
                description: current.description || 'imported-current'
            });
        } else {
            found.active = !!current.active;
        }
    }

    const activeEntry = state.keyHistory.keys.find(k => k.active);
    if (activeEntry) {
        state.currentVersion = activeEntry.version;
        try {
            state.currentKey = Buffer.from(activeEntry.key, 'base64');
        } catch (e) {
            console.error('[KEY-MGR] Invalid base64 for active key, clearing currentKey:', e.message);
            state.currentKey = null;
            state.currentVersion = null;
        }
    } else if (state.keyHistory.keys.length > 0) {
        const last = state.keyHistory.keys[state.keyHistory.keys.length - 1];
        last.active = true;
        state.currentVersion = last.version;
        try {
            state.currentKey = Buffer.from(last.key, 'base64');
        } catch (e) {
            console.error('[KEY-MGR] Invalid base64 in last key, clearing currentKey:', e.message);
            state.currentKey = null;
            state.currentVersion = null;
        }
    } else {
        state.currentKey = null;
        state.currentVersion = null;
    }
}

// Simple audit/event logging to audit dir
function logEvent(type, data = {}) {
    try {
        const auditDir = config.audit.auditDir;
        _ensureDir(auditDir);
        const filePath = path.join(auditDir, 'encryption-events.jsonl');
        const entry = {
            type,
            ...data,
            '@timestamp': new Date().toISOString()
        };
        try {
            fs.appendFileSync(filePath, JSON.stringify(entry) + '\n', { mode: 0o600 });
        } catch (e) {
            console.warn('[KEY-MGR] append to audit failed, fallback write:', e.message);
            _atomicWriteFile(filePath, JSON.stringify(entry) + '\n', 0o600);
        }
    } catch (e) {
        console.error('[KEY-MGR] Failed to log event:', e.message);
    }
}

// Expand path helper (handles ~, $HOME, ${HOME})
function _expandPath(p) {
    if (typeof p !== 'string') return p;
    const home = os.homedir();
    return p.replace(/^~(?=$|\/|\\)/, home).replace(/\$\{HOME\}/g, home).replace(/\$HOME/g, home);
}

// Public API
const KeyManager = {
    init: (override = {}) => {
        try {
            if (override && typeof override === 'object') {
                config = { ...config, ...override };
                if (override.keys) config.keys = { ...config.keys, ...override.keys };
                if (override.encryption_storage) config.encryption_storage = { ...config.encryption_storage, ...override.encryption_storage };
                if (override.audit) config.audit = { ...config.audit, ...override.audit };
            }

            if (!config.encryption_storage.currentKeyFile) throw new Error('currentKeyFile not configured');
            if (!config.encryption_storage.keyHistoryFile) throw new Error('keyHistoryFile not configured');
            if (!config.audit.auditDir) throw new Error('auditDir not configured');

            config.encryption_storage.currentKeyFile = _expandPath(config.encryption_storage.currentKeyFile);
            config.encryption_storage.keyHistoryFile = _expandPath(config.encryption_storage.keyHistoryFile);
            config.audit.auditDir = _expandPath(config.audit.auditDir);

            _ensureDir(path.dirname(config.encryption_storage.currentKeyFile));
            _ensureDir(path.dirname(config.encryption_storage.keyHistoryFile));
            _ensureDir(config.audit.auditDir);

            // load existing keys
            _loadKeyFiles();

            if (config.encryption.enabled && !state.currentKey) {
                console.log('[KEY-MGR] No active key found; generating new key (rotation enabled)');
                const entry = KeyManager.createKey({ description: 'auto-generated-on-init' });
                KeyManager.activateKey(entry.version);
                KeyManager.persist();
            } else if (!config.encryption.enabled && state.currentKey) {
                console.warn('[KEY-MGR] ⚠️ Encryption disabled in config, but keys exist');
            }

            state.metricsTimer = setInterval(_persistMetrics, config.metricsPersistIntervalMs || 5 * 60 * 1000);

            KeyManager.startRotationScheduler();

            state.initialized = true;
            console.log('[KEY-MGR] Initialized; currentVersion=' + (state.currentVersion || 'none'));
            return true;
        } catch (e) {
            console.error('[KEY-MGR] Initialization failed:', e.message);
            state.initialized = false;
            return false;
        }
    },

    // Create a new key (does not automatically activate)
    createKey: ({ version = null, description = '' } = {}) => {
        const newKeyBase64 = _generateKeyBase64();
        const maxVer = state.keyHistory.keys.reduce((m, k) => Math.max(m, k.version || 0), 0);
        const newVersion = Number.isInteger(version) ? version : (maxVer + 1 || 1);
        const entry = {
            version: newVersion,
            key: newKeyBase64,
            created: new Date().toISOString(),
            active: false,
            description: description || ''
        };
        state.keyHistory.keys.push(entry);
        // NOTE: createKey is not counted as a rotation event by itself; rotateKeys() increments.
        return entry;
    },

    // Activate a key by version (deactivates others)
    activateKey: (version) => {
        const target = state.keyHistory.keys.find(k => k.version === version);
        if (!target) throw new Error('Key version not found: ' + version);

        if (!_validateKeyEntry(target)) {
            throw new Error('Invalid key material for version ' + version);
        }

        state.keyHistory.keys.forEach(k => k.active = (k.version === version));
        state.currentVersion = version;
        try {
            state.currentKey = Buffer.from(target.key, 'base64');
        } catch (e) {
            throw new Error('Failed to decode key material for version ' + version + ': ' + e.message);
        }

        KeyManager.persist();
        return { version: state.currentVersion, activatedAt: new Date().toISOString() };
    },

    // Rotate keys: create a new key, activate it, retire old keys beyond retention
    rotateKeys: ({ reason = 'scheduled' } = {}) => {
        return _withLock('rotate', () => {
            if (!config.keys.rotationEnabled) throw new Error('Rotation disabled in config');

            const entry = KeyManager.createKey({ description: `rotation:${reason}` });
            state.keyHistory.keys.forEach(k => k.active = false);
            entry.active = true;
            state.currentVersion = entry.version;
            try { state.currentKey = Buffer.from(entry.key, 'base64'); } catch (e) { state.currentKey = null; }

            const retain = config.keys.maxKeysRetained || 5;
            state.keyHistory.keys.sort((a, b) => b.version - a.version);
            if (state.keyHistory.keys.length > retain) {
                const toRemove = state.keyHistory.keys.slice(retain);
                state.keyHistory.keys = state.keyHistory.keys.slice(0, retain);
                logEvent('key_retired_batch', { removed: toRemove.map(k => k.version), reason });
            }

            _incrementMetric('keyRotations');
            KeyManager.persist();
            logEvent('key_rotation', { newVersion: entry.version, reason });
            return { version: entry.version, created: entry.created };
        });
    },

    // Persist both current key file and history to configured locations
    persist: () => {
        return _withLock('persist', () => {
            try {
                _saveKeyHistory();
                _saveCurrentKeyFile();
                _persistMetrics();
            } catch (e) {
                console.error('[KEY-MGR] Persist failed:', e.message);
                throw e;
            }
        });
    },

    // Force reload keys from files (useful after manual file edits)
    reload: () => {
        _loadKeyFiles();
        return { currentVersion: state.currentVersion, keysCount: state.keyHistory.keys.length };
    },

    // Get current key buffer (for encryption/decryption operations)
    getCurrentKeyBuffer: () => {
        if (!state.currentKey) return null;
        return Buffer.from(state.currentKey);
    },

    // Get metadata for current key
    getKeyMetadata: (version = null) => {
        const ver = version === null ? state.currentVersion : version;
        const entry = state.keyHistory.keys.find(k => k.version === ver);
        if (!entry) return null;
        return { version: entry.version, created: entry.created, active: !!entry.active, description: entry.description || '' };
    },

    listKeys: () => state.keyHistory.keys.map(k => ({ version: k.version, created: k.created, active: !!k.active, description: k.description || '' })),

    // Metrics helpers
    incrementMetric: (name) => _incrementMetric(name),
    getMetrics: () => ({ ...state.metrics }),
    getMetricsArchive: () => [...state.metricsArchive],

    // Rotation scheduler: checks interval and rotates if age exceeded
    startRotationScheduler: () => {
        try {
            if (!config.keys.rotationEnabled) return;
            if (state.rotationTimer) return;
            state.rotationTimer = setInterval(() => {
                try {
                    const active = state.keyHistory.keys.find(k => k.active);
                    if (!active) return;
                    const createdAt = new Date(active.created).getTime();
                    const ageMs = Date.now() - createdAt;
                    const rotationIntervalMs = (config.keys.rotationIntervalDays || 30) * 24 * 60 * 60 * 1000;
                    if (ageMs > rotationIntervalMs) {
                        console.log('[KEY-MGR] Rotation interval exceeded, scheduling rotation...');
                        const jitter = Math.floor(Math.random() * (60 * 60 * 1000)); // up to 1 hour
                        setTimeout(() => {
                            try { KeyManager.rotateKeys({ reason: 'scheduled-interval' }); } catch (e) { console.warn('[KEY-MGR] Scheduled rotation failed:', e.message); }
                        }, jitter);
                    }
                } catch (e) { console.warn('[KEY-MGR] Rotation scheduler error:', e.message); }
            }, 6 * 60 * 60 * 1000);
        } catch (e) { console.error('[KEY-MGR] Failed to start rotation scheduler:', e.message); }
    },

    stopRotationScheduler: () => {
        if (state.rotationTimer) { clearInterval(state.rotationTimer); state.rotationTimer = null; }
    },

    // Persist and shutdown hooks for graceful server termination
    shutdown: () => {
        try {
            if (state.metricsTimer) { clearInterval(state.metricsTimer); state.metricsTimer = null; }
            KeyManager.persist();
            KeyManager.stopRotationScheduler();
            console.log('[KEY-MGR] Shutdown complete, persisted state.');
        } catch (e) {
            console.warn('[KEY-MGR] Shutdown encountered errors:', e.message);
        }
    },

    // Get initialization state
    isInitialized: () => state.initialized
};

module.exports = KeyManager;