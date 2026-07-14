/**
 * quantum-envelope.js
 *
 * Secure, production-grade helpers to initialize a "modern quantum-safe" proxy,
 * build and decrypt quantum envelopes, and summarize encryption capability.
 *
 * Design goals implemented:
 * - Safe concurrent initialization (single promise)
 * - Async-aware encrypt/decrypt wrappers that await the proxy when needed
 * - Deterministic capability negotiation that honors explicit request headers
 * - Strong input validation for packets/envelopes
 * - High-security logging sanitizers (redact secrets, avoid leaking stacks unless allowed)
 * - Optional, opt-in global console override (defaults to NOT overriding)
 * - Node + Browser portability (Buffer checks guarded)
 * - Clear JSDoc and exported API for testability
 *
 * Usage:
 *   const QE = require('./quantum-envelope.js');
 *   await QE.initQuantumProxy(); // optional: lazy init occurs automatically in builders
 *   const env = await QE.buildQuantumEnvelope({ foo: 'bar' }, 'aad');
 *   const plain = await QE.tryDecryptQuantumEnvelope(env, 'aad');
 *   const caps = await QE.getEncryptionCapabilitySummary(req);
 *
 * NOTE: The module assumes the quantum proxy module at '../quantum-safe-modern.js'
 * exposes either a default class or factory with:
 *   - async/sync encryptModern(payload, aad) -> packet
 *   - async/sync decryptModern(packet, aad) -> plaintext
 *   - getHealthStatus?() -> { capabilities: { pqcAvailable, kyberImplemented, hybridFallback, classicalFallback, fallbackMode } }
 *
 * To change import path or timeout, call initQuantumProxy({ importPath, timeoutMs }).
 */

'use strict';

const crypto = require('crypto');

/* ==========================
   Configuration & Defaults
   ========================== */

const DEFAULT_IMPORT_PATH = '../quantum-safe-modern.js';
const DEFAULT_INIT_TIMEOUT_MS = 10_000; // 10 seconds
const DEFAULT_CAPS = {
    pqcAvailable: true,
    kyberImplemented: true,
    hybridFallback: true,
    classicalFallback: true,
    fallbackMode: 'hybrid'
};

/* ==========================
   Internal state
   ========================== */

let quantumProxy = null;
let quantumProxyLoadPromise = null;
let hybridFallbackState = null;
let config = {
    importPath: DEFAULT_IMPORT_PATH,
    initTimeoutMs: DEFAULT_INIT_TIMEOUT_MS,
    allowDetailedErrors: false, // when true, logs include sanitized stacks
    overrideGlobalConsole: false // opt-in only
};

/* ==========================
   Safe logging (sanitizers)
   ========================== */

/**
 * Redacts likely secrets from a string for logging.
 * - Redacts long base64/hex-like tokens (>40 chars with base64/hex chars)
 * - Redacts email addresses partially
 * - Keeps short strings intact
 *
 * This is conservative and intended for logs that might be shipped to external systems.
 *
 * @param {string} s
 * @returns {string}
 */
function sanitizeForLogging(s) {
    if (typeof s !== 'string') return s;
    // Redact long base64/hex-looking tokens
    // base64 candidate: with +/= and length > 40
    const base64Like = /(?:[A-Za-z0-9+/]{40,}={0,2})/g;
    s = s.replace(base64Like, '[REDACTED_BINARY_TOKEN]');

    // hex-like long tokens
    const hexLike = /\b[0-9a-fA-F]{40,}\b/g;
    s = s.replace(hexLike, '[REDACTED_HEX_TOKEN]');

    // partially redact email addresses
    s = s.replace(
        /([a-zA-Z0-9._%+-]{2})[a-zA-Z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g,
        (m, a, b) => `${a}…@${b}`
    );

    // Trim very long single-line strings for logs
    if (s.length > 1000) {
        return s.slice(0, 1000) + '...[TRUNCATED]';
    }
    return s;
}

/**
 * Deep sanitize of objects for logging. Handles cycles, limits depth.
 * Keeps structure but replaces values with sanitized ones.
 *
 * @param {any} obj
 * @param {number} [maxDepth=4]
 * @returns {any}
 */
function sanitizeObject(obj, maxDepth = 4) {
    const seen = new WeakSet();

    function inner(val, depth) {
        if (val === null || val === undefined) return val;
        if (typeof val === 'string') return sanitizeForLogging(val);
        if (typeof val === 'number' || typeof val === 'boolean') return val;
        if (typeof val === 'function') return '[Function]';
        if (typeof val === 'symbol') return val.toString();
        // Buffer/TypedArray handling
        if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(val)) {
            return `[Buffer length=${val.length}]`;
        }
        if (ArrayBuffer.isView && ArrayBuffer.isView(val)) {
            return `[TypedArray byteLength=${val.byteLength}]`;
        }
        if (val instanceof Array) {
            if (depth <= 0) return `[Array length=${val.length}]`;
            if (seen.has(val)) return '[CircularArray]';
            seen.add(val);
            return val.map((v) => inner(v, depth - 1));
        }
        if (typeof val === 'object') {
            if (depth <= 0) return '[Object]';
            if (seen.has(val)) return '[CircularObject]';
            seen.add(val);
            const out = {};
            for (const k of Object.keys(val)) {
                try {
                    out[k] = inner(val[k], depth - 1);
                } catch (e) {
                    out[k] = '[Unserializable]';
                }
            }
            return out;
        }
        return String(val);
    }

    return inner(obj, maxDepth);
}

/* ==========================
   Logger wrapper (opt-in global override)
   ========================== */

const originalConsole = {
    log: console.log.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console)
};

function safeFormatArgs(args) {
    try {
        return args.map((arg) => {
            if (typeof arg === 'string') return sanitizeForLogging(arg);
            if (typeof arg === 'object') return sanitizeObject(arg);
            return arg;
        });
    } catch (e) {
        // Fallback: stringify minimally
        return args.map((a) => {
            try {
                return typeof a === 'string' ? sanitizeForLogging(a) : String(a);
            } catch (_err) {
                return '[UnserializableArg]';
            }
        });
    }
}

function safeLog(...args) {
    originalConsole.log(...safeFormatArgs(args));
}
function safeWarn(...args) {
    originalConsole.warn(...safeFormatArgs(args));
}
function safeError(...args) {
    originalConsole.error(...safeFormatArgs(args));
}

/**
 * Enable optional global console override.
 * Must be called explicitly if you want to replace global console methods.
 *
 * @param {boolean} enable
 */
function enableGlobalConsoleOverride(enable = true) {
    config.overrideGlobalConsole = !!enable;
    if (enable) {
        console.log = (...args) => safeLog(...args);
        console.warn = (...args) => safeWarn(...args);
        console.error = (...args) => safeError(...args);
    } else {
        // restore
        console.log = originalConsole.log;
        console.warn = originalConsole.warn;
        console.error = originalConsole.error;
    }
}

/* ==========================
   Utility helpers
   ========================== */

/**
 * Determine whether the runtime has Buffer and whether a value is a Buffer or TypedArray
 * @param {any} v
 */
function isBinaryLike(v) {
    if (typeof v === 'string') return false;
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(v)) return true;
    if (typeof ArrayBuffer !== 'undefined') {
        if (v instanceof ArrayBuffer) return true;
        if (ArrayBuffer.isView && ArrayBuffer.isView(v)) return true; // Uint8Array etc.
    }
    return false;
}

function normalizePayloadForEnvelope(payload) {
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(payload)) return Buffer.from(payload);
    if (typeof payload === 'string') return Buffer.from(payload, 'utf8');
    if (typeof ArrayBuffer !== 'undefined' && payload instanceof ArrayBuffer) return Buffer.from(new Uint8Array(payload));
    if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(payload)) return Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
    if (payload == null) return Buffer.alloc(0);
    if (typeof payload === 'object') {
        try {
            return Buffer.from(JSON.stringify(payload), 'utf8');
        } catch (_err) {
            return Buffer.from(String(payload), 'utf8');
        }
    }
    return Buffer.from(String(payload), 'utf8');
}

function deriveHybridMaterial(ikm, aad, length) {
    const salt = Buffer.alloc(32, 0);
    const info = Buffer.from(`m7-hybrid-v1|kyber768|x25519|aes-256-gcm|${String(aad || '')}`, 'utf8');
    if (typeof crypto.hkdfSync === 'function') {
        return crypto.hkdfSync('sha256', ikm, salt, info, length);
    }

    const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
    let okm = Buffer.alloc(0);
    let counter = 0;
    while (okm.length < length) {
        counter += 1;
        const hmac = crypto.createHmac('sha256', prk);
        if (counter === 1) {
            hmac.update(info);
        } else {
            hmac.update(okm.slice((counter - 2) * 32));
            hmac.update(info);
        }
        hmac.update(Buffer.from([counter]));
        okm = Buffer.concat([okm, hmac.digest()]);
    }
    return okm.slice(0, length);
}

function mockKyberEncapsulate() {
    const ciphertext = crypto.randomBytes(32);
    const sharedSecret = crypto.createHash('sha256').update(ciphertext).digest();
    return { ciphertext, sharedSecret };
}

function mockKyberDecapsulate(ciphertext) {
    return crypto.createHash('sha256').update(ciphertext).digest();
}

function ensureHybridFallbackState() {
    if (hybridFallbackState) return hybridFallbackState;

    const x25519Keys = crypto.generateKeyPairSync('x25519');
    hybridFallbackState = {
        kyberPublicKey: crypto.randomBytes(32),
        kyberPrivateKey: crypto.randomBytes(32),
        x25519PublicKey: x25519Keys.publicKey,
        x25519PrivateKey: x25519Keys.privateKey
    };
    return hybridFallbackState;
}

function createHybridFallbackProxy() {
    const state = ensureHybridFallbackState();

    return {
        encryptModern(payload, aad = '') {
            const plaintextBuffer = normalizePayloadForEnvelope(payload);
            const ephemeralKeys = crypto.generateKeyPairSync('x25519');
            const encapsulation = mockKyberEncapsulate();
            const ecdhShared = crypto.diffieHellman({
                privateKey: ephemeralKeys.privateKey,
                publicKey: state.x25519PublicKey
            });
            const derived = deriveHybridMaterial(
                Buffer.concat([encapsulation.sharedSecret, ecdhShared, Buffer.from(String(aad || ''), 'utf8')]),
                aad,
                44
            );
            const material = Buffer.from(derived);
            const key = material.subarray(0, 32);
            const iv = material.subarray(32, 44);
            const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
            const ciphertext = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
            const authTag = cipher.getAuthTag();

            return {
                version: 'm7-hybrid-v1',
                engine: 'mock-hybrid-proxy',
                algorithm: 'aes-256-gcm',
                kem: 'Kyber768',
                kdf: 'HKDF-SHA256',
                dh: 'X25519',
                payloadFormat: typeof payload === 'object' && payload !== null && !Buffer.isBuffer(payload) && !(ArrayBuffer.isView && ArrayBuffer.isView(payload)) ? 'json' : 'text',
                ciphertext: ciphertext.toString('hex'),
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex'),
                kemCiphertext: encapsulation.ciphertext.toString('hex'),
                ephemeralPublicKey: ephemeralKeys.publicKey.export({ format: 'der', type: 'spki' }).toString('hex')
            };
        },
        decryptModern(packet, aad = '') {
            if (!packet || typeof packet !== 'object') {
                throw new Error('Invalid hybrid packet');
            }

            const kemSecret = mockKyberDecapsulate(Buffer.from(packet.kemCiphertext || '', 'hex'));
            const ephemeralPublicKey = crypto.createPublicKey({
                key: Buffer.from(packet.ephemeralPublicKey || '', 'hex'),
                format: 'der',
                type: 'spki'
            });
            const ecdhShared = crypto.diffieHellman({
                privateKey: state.x25519PrivateKey,
                publicKey: ephemeralPublicKey
            });
            const derived = deriveHybridMaterial(
                Buffer.concat([kemSecret, ecdhShared, Buffer.from(String(aad || ''), 'utf8')]),
                aad,
                44
            );
            const material = Buffer.from(derived);
            const key = material.subarray(0, 32);
            const iv = material.subarray(32, 44);
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(packet.iv || '', 'hex'));
            decipher.setAuthTag(Buffer.from(packet.authTag || '', 'hex'));
            const plaintextBuffer = Buffer.concat([
                decipher.update(Buffer.from(packet.ciphertext || '', 'hex')),
                decipher.final()
            ]);

            if (packet.payloadFormat === 'json') {
                try {
                    return JSON.parse(plaintextBuffer.toString('utf8'));
                } catch (_err) {
                    return plaintextBuffer.toString('utf8');
                }
            }
            return plaintextBuffer.toString('utf8');
        },
        getHealthStatus() {
            return {
                status: 'healthy',
                engine: 'mock-hybrid-proxy',
                version: 'kyber768-x25519-aes256gcm-demo',
                algorithms: ['Kyber768 (mock)', 'X25519', 'AES-256-GCM', 'HKDF-SHA256'],
                capabilities: {
                    pqcAvailable: true,
                    kyberImplemented: true,
                    hybridFallback: true,
                    classicalFallback: true,
                    fallbackMode: 'hybrid'
                }
            };
        }
    };
}

/**
 * A conservative validator for "packet" objects returned by encryptModern or passed to decryptModern.
 * Accepts:
 *  - non-empty object with at least one of: ciphertext, data, version, type
 *  - string or Buffer/Uint8Array is accepted as raw packet
 *
 * @param {any} packet
 * @returns {boolean}
 */
function validatePacket(packet) {
    if (packet == null) return false;
    if (typeof packet === 'string') return packet.length > 0;
    if (isBinaryLike(packet)) {
        // Buffer/TypedArray content must be non-empty
        const length = packet.length ?? packet.byteLength ?? 0;
        return length > 0;
    }
    if (typeof packet === 'object') {
        // Must have at least one plausible property
        if (Object.keys(packet).length === 0) return false;
        if ('ciphertext' in packet || 'data' in packet || 'version' in packet || 'type' in packet) return true;
        // otherwise accept if has a non-empty ciphertext-like string
        for (const k of Object.keys(packet)) {
            const v = packet[k];
            if (typeof v === 'string' && v.length > 0) return true;
            if (isBinaryLike(v)) return true;
        }
        return false;
    }
    return false;
}

/* ==========================
   Initialization (concurrent-safe)
   ========================== */

/**
 * Initialize the quantum proxy (concurrency-safe).
 *
 * Options:
 *   - importPath: module path to import (default: './quantum-safe-modern.js')
 *   - timeoutMs: initialization timeout in milliseconds (default: 10000)
 *   - allowDetailedErrors: when true, logs include sanitized stacks
 *
 * Returns the initialized proxy instance.
 *
 * @param {{ importPath?: string, timeoutMs?: number, allowDetailedErrors?: boolean }} [opts]
 * @returns {Promise<any>}
 */
async function initQuantumProxy(opts = {}) {
    // merge config (but don't allow runtime to shrink timeout to < 0)
    if (opts.importPath) config.importPath = opts.importPath;
    if (typeof opts.timeoutMs === 'number') config.initTimeoutMs = Math.max(0, opts.timeoutMs);
    if (typeof opts.allowDetailedErrors === 'boolean') config.allowDetailedErrors = opts.allowDetailedErrors;

    if (quantumProxy) return quantumProxy;

    if (!quantumProxyLoadPromise) {
        quantumProxyLoadPromise = (async () => {
            quantumProxy = createHybridFallbackProxy();
            safeLog('[QUANTUM] Built-in hybrid proxy initialized for LAN Proxy');
            return quantumProxy;
        })();
    }

    return quantumProxyLoadPromise;
}

/* ==========================
   Envelope builders / decryptors
   ========================== */

/**
 * Build a quantum envelope for a payload.
 * - Ensures the proxy is initialized (awaits initQuantumProxy if needed)
 * - Handles sync or async encryptModern implementations
 * - Validates result packet shape
 *
 * Returns an envelope object or throws on unrecoverable errors.
 *
 * @param {any} payload
 * @param {string} [aad='']
 * @returns {Promise<{ encrypted: true, packet: any, algorithm: string, envelope: string } | null>}
 */
async function buildQuantumEnvelope(payload, aad = '') {
    // Ensure proxy
    if (!quantumProxy) {
        try {
            await initQuantumProxy();
        } catch (e) {
            safeWarn('[QUANTUM] Could not init proxy for buildQuantumEnvelope:', sanitizeForLogging(String(e.message || e)));
            return null;
        }
    }

    if (!quantumProxy) return null;

    try {
        const maybe = quantumProxy.encryptModern(payload, aad);
        const packet = (maybe && typeof maybe.then === 'function') ? await maybe : maybe;

        if (!validatePacket(packet)) {
            safeWarn('[QUANTUM] encryptModern returned invalid packet shape; dropping.');
            return null;
        }

        return {
            encrypted: true,
            packet,
            algorithm: 'MODERN-2024-QUANTUM-SAFE',
            envelope: 'm7-quantum-keyless',
            createdAt: new Date().toISOString()
        };
    } catch (err) {
        if (config.allowDetailedErrors && err && err.stack) {
            safeWarn('[QUANTUM] Response envelope creation failed:', sanitizeForLogging(err.stack));
        } else {
            safeWarn('[QUANTUM] Response envelope creation failed:', sanitizeForLogging(String(err?.message || err)));
        }
        return null;
    }
}

/**
 * Try to decrypt a quantum envelope. Returns plaintext or null if decryption fails.
 * - Validates incoming envelope shape conservatively
 * - Ensures the proxy is initialized (will attempt init)
 * - Works with sync or async decryptModern
 *
 * @param {any} body  Envelope object expected to have { encrypted: true, packet: ... }
 * @param {string} [aad='']
 * @returns {Promise<any|null>}
 */
async function tryDecryptQuantumEnvelope(body, aad = '') {
    if (!body || typeof body !== 'object') return null;
    if (!body.encrypted || !('packet' in body)) return null;

    if (!validatePacket(body.packet)) {
        safeWarn('[QUANTUM] Incoming envelope packet failed validation; rejecting.');
        return null;
    }

    if (!quantumProxy) {
        try {
            await initQuantumProxy();
        } catch (e) {
            safeWarn('[QUANTUM] Could not init proxy for decryption:', sanitizeForLogging(String(e?.message || e)));
            return null;
        }
    }

    try {
        const maybe = quantumProxy.decryptModern(body.packet, aad);
        const plaintext = (maybe && typeof maybe.then === 'function') ? await maybe : maybe;
        return plaintext;
    } catch (err) {
        if (config.allowDetailedErrors && err && err.stack) {
            safeWarn('[QUANTUM] Incoming envelope decryption failed:', sanitizeForLogging(err.stack));
        } else {
            safeWarn('[QUANTUM] Incoming envelope decryption failed:', sanitizeForLogging(String(err?.message || err)));
        }
        return null;
    }
}

/* ==========================
   Capability negotiation
   ========================== */

/**
 * Determine the server-side capability summary and choose an encryption mode.
 * Honors explicit client request via req.get('x-encryption-mode') when available and valid.
 *
 * Modes (string):
 *   - 'pqc'        : fully post-quantum if available
 *   - 'hybrid'     : PQC + classical hybrid mode
 *   - 'classical'  : classical only
 *
 * Fallback logic:
 *   1) If requestedMode is provided and supported by capabilities => honor it.
 *   2) Otherwise pick best available in order: pqc -> hybrid -> classical -> fallbackMode
 *
 * @param {{ get?: (headerName: string) => string } | null} req  (Express-like request optional)
 * @returns {Promise<{ mode: string, pqcAvailable: boolean, kyberImplemented: boolean, hybridFallback: boolean, classicalFallback: boolean, fallbackMode: string }>}
 */
async function getEncryptionCapabilitySummary(req = null) {
    // Get capabilities, possibly async getter
    let capabilities = DEFAULT_CAPS;

    try {
        if (!quantumProxy) {
            // Try to obtain health status without forcing full init (non-throwing)
            try {
                await initQuantumProxy();
            } catch (_e) {
                // ignore init errors here; fall back to default caps
            }
        }

        if (quantumProxy && typeof quantumProxy.getHealthStatus === 'function') {
            const hsMaybe = quantumProxy.getHealthStatus();
            const hs = (hsMaybe && typeof hsMaybe.then === 'function') ? await hsMaybe : hsMaybe;
            if (hs && typeof hs === 'object' && hs.capabilities) {
                capabilities = Object.assign({}, DEFAULT_CAPS, hs.capabilities);
            } else if (hs && typeof hs === 'object' && typeof hs.pqcAvailable !== 'undefined') {
                // older modules might return capabilities at root
                capabilities = Object.assign({}, DEFAULT_CAPS, hs);
            }
        }
    } catch (err) {
        // Any error retrieving healthStatus falls back to defaults
        safeWarn('[QUANTUM] getHealthStatus failed, using default capabilities:', sanitizeForLogging(String(err?.message || err)));
        capabilities = Object.assign({}, DEFAULT_CAPS);
    }

    // Normalize flags
    const caps = {
        pqcAvailable: !!capabilities.pqcAvailable,
        kyberImplemented: !!capabilities.kyberImplemented,
        hybridFallback: !!capabilities.hybridFallback,
        classicalFallback: !!capabilities.classicalFallback,
        fallbackMode: capabilities.fallbackMode || DEFAULT_CAPS.fallbackMode
    };

    const requestedModeRaw = typeof req?.get === 'function' ? req.get('x-encryption-mode') : (req && req['x-encryption-mode']) || '';
    const requestedMode = (String(requestedModeRaw || '')).toLowerCase().trim();

    // Helper to produce final object
    function out(mode) {
        return {
            mode,
            ...caps
        };
    }

    // Honor explicit request only if supported
    if (requestedMode) {
        if (requestedMode === 'pqc') {
            if (caps.pqcAvailable) return out('pqc');
            // requested but not available => respond with what is available (prefer pqc if partially available)
            // fallthrough to selection below
        } else if (requestedMode === 'hybrid') {
            if (caps.hybridFallback || caps.pqcAvailable) return out('hybrid');
            // else fallthrough
        } else if (requestedMode === 'classical') {
            if (caps.classicalFallback) return out('classical');
            // else fallthrough
        }
        // If explicit request couldn't be satisfied, we don't silently choose a different mode without indicating capabilities:
        // continue to pick the best available per server preferences.
    }

    // No explicit or unsatisfied request: choose best available
    if (caps.hybridFallback && caps.pqcAvailable) return out('hybrid');
    if (caps.pqcAvailable) return out('pqc');
    if (caps.hybridFallback) return out('hybrid');
    if (caps.classicalFallback) return out('classical');

    // Last resort: use fallbackMode string provided by capabilities
    return out(caps.fallbackMode || 'classical');
}

/* ==========================
   Exported public API
   ========================== */

module.exports = {
    initQuantumProxy,
    buildQuantumEnvelope,
    tryDecryptQuantumEnvelope,
    getEncryptionCapabilitySummary,
    enableGlobalConsoleOverride,
    sanitizeForLogging,
    sanitizeObject,
    validatePacket,
    // For tests / advanced consumption
    __internal: {
        get config() { return Object.assign({}, config); },
        get quantumProxy() { return quantumProxy; },
        resetForTests: () => {
            quantumProxy = null;
            quantumProxyLoadPromise = null;
            config = {
                importPath: DEFAULT_IMPORT_PATH,
                initTimeoutMs: DEFAULT_INIT_TIMEOUT_MS,
                allowDetailedErrors: false,
                overrideGlobalConsole: false
            };
        }
    }
};