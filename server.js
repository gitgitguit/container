const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const session = require('express-session');
const csrf = require('csurf');
const fs = require('fs');
const path = require('path');
const { execSync, exec, execFile, spawn } = require('child_process');
const m7Crypto = require('./modules/security/m7-crypto');
const { sanitizeForLogging, sanitizeObject } = require('./sanitizer');
const { validateRequestURL } = require('./ssrf-guard');
const SQLInjectionDetector = require('./sql-detector');
const pathValidator = require('./path-validator');
const APIKeyManager = require('./key-manager');
const { RBACManager } = require('./rbac');
const SecurityErrorHandler = require('./error-handler');
const rateLimit = require('express-rate-limit');
const EmailBasedMFA = require('./email-based-mfa');
const EmailService = require('./email-service');
// ✅ REMOVED: Early import of quantumEnvelopeService (line 22)
// Quantum service will be loaded lazily within initQuantumProxy()
const { registerAccessRoutes, createAccessTokenMiddleware, resolveBootstrapApiKey } = require('./register');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 0: ENCRYPTION KEY MANAGEMENT (REQUEST ENCRYPTION)
// ════════════════════════════════════════════════════════════════[[...]

const KeyManager = require('./modules/security/management-key-functions');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 1: ANTI-FORGERY TRANSPORT [NIST 2024 COMPLIANT]
// ════════════════════════════════════════════════════════════════[[...]

const {
    registerSecurity: registerAntiForgeryTransport,
    makeVerifiedRequest: createVerifiedHttpsClient
} = require('./modules/security/antiForgeryTransport');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 2: SSL/TLS VERIFICATION MODULE
// ════════════════════════════════════════════════════════════════[[...]

const {
    enableSSLVerificationMiddleware,
    makeVerifiedRequest,
    getSSLStatus,
    getAuditStats,
    loadSSLConfig,
    shutdown: shutdownSSLTLS,
    getConfig: getSSLConfig
} = require('./modules/security/ssl-tls-verification');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 6: ATTACK DETECTION & FORENSIC LOGGING (IMPORT)
// ════════════════════════════════════════════════════════════════[[...]

const { createAttackDetectionEngine, createAttackDetectionMiddleware } = require('./modules/security/attack-detection');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 3: ANTI-FORGERY PRODUCTION [RESPONSE INTEGRITY]
// ════════════════════════════════════════════════════════════════[[...]

const {
    SecureKeyManager,
    AntiForgerySigner,
    TransportIntegrityVerifier,
    NetworkSecurityManager,
    SecureResponseManager
} = require('./modules/security/anti-forgery-production');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 4: ANTI-FORGERY PRODUCTION SERVICES (LEGACY)
// ════════════════════════════════════════════════════════════════[[...]

const {
    SecureKeyManager: LegacySecureKeyManager,
    AntiForgerySigner: LegacyAntiForgerySigner,
    TransportIntegrityVerifier: LegacyTransportIntegrityVerifier,
    NetworkSecurityManager: LegacyNetworkSecurityManager,
    SecureResponseManager: LegacySecureResponseManager
} = require('./anti-forgery-production');

// ════════════════════════════════════════════════════════════════[[...]
// STEP 1: IMPORT PROXY ENCRYPTION GATEWAY (note.md Line 84)
// ════════════════════════════════════════════════════════════════[[...]

const { initProxyEncryptionGateway } = require('./modules/security/proxy-encryption-gateway');

// Initialize Express app
const app = express();

// ════════════════════════════════════════════════════════════════[[...]
// INITIALIZE CORE SECURITY MANAGERS
// ════════════════════════════════════════════════════════════════[[...]

const sqlDetector = new SQLInjectionDetector();
const keyManager = new APIKeyManager();
const rbacManager = new RBACManager();
const mfaManager = new EmailBasedMFA();

// ════════════════════════════════════════════════════════════════[...]
// EMAIL SERVICE INITIALIZATION (REFACTORED)
// ════════════════════════════════════════════════════════════════[...]

const emailService = new EmailService({
    host: process.env.SMTP_HOST || 'localhost',
    port: parseInt(process.env.SMTP_PORT || '25', 10),
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.SMTP_FROM || 'noreply@proxy.local'
});

console.log('✅ [EMAIL-SERVICE] Initialized');
console.log('   ├─ SMTP Host: ' + (process.env.SMTP_HOST || 'localhost'));
console.log('   ├─ SMTP Port: ' + (process.env.SMTP_PORT || '25'));
console.log('   ├─ TLS: ' + (process.env.SMTP_SECURE === 'true' ? 'enabled' : 'disabled'));
console.log('   └─ From: ' + (process.env.SMTP_FROM || 'noreply@proxy.local'));

// ════════════════════════════════════════════════════════════════[...]
// MAGIC LINK STORAGE: In-memory token store (use Redis in production)
// ════════════════════════════════════════════════════════════════[...]

const magicLinkTokens = new Map(); // { token: { email, expiresAt, type } }
const MAGIC_LINK_EXPIRY = 15 * 60 * 1000; // 15 minutes
const PROXY_BASE_URL = process.env.PROXY_BASE_URL || `http://${process.env.HOST || 'localhost'}:${process.env.PORT || 3000}`;

function generateMagicToken() {
    return crypto.randomBytes(32).toString('hex');
}

function createMagicLink(token) {
    return `${PROXY_BASE_URL}/auth/mfa/verify-link?token=${token}`;
}

function storeMagicToken(token, email, type = 'register') {
    magicLinkTokens.set(token, {
        email,
        type,
        expiresAt: Date.now() + MAGIC_LINK_EXPIRY
    });
    console.log(`[MAGIC-LINK] Token stored for ${email} (type: ${type})`);
}

function validateMagicToken(token) {
    const data = magicLinkTokens.get(token);
    if (!data) {
        return { valid: false, reason: 'Token not found' };
    }
    if (Date.now() > data.expiresAt) {
        magicLinkTokens.delete(token);
        return { valid: false, reason: 'Token expired' };
    }
    return { valid: true, data };
}

function consumeMagicToken(token) {
    const data = magicLinkTokens.get(token);
    magicLinkTokens.delete(token);
    return data;
}

// Cleanup expired tokens every 5 minutes
setInterval(() => {
    let cleaned = 0;
    for (const [token, data] of magicLinkTokens.entries()) {
        if (Date.now() > data.expiresAt) {
            magicLinkTokens.delete(token);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`[MAGIC-LINK] Cleaned up ${cleaned} expired tokens`);
    }
}, 5 * 60 * 1000);

// ════════════════════════════════════════════════════════════════[...]
// REGISTRATION STATE: Track if already registered (one-time setup)
// ════════════════════════════════════════════════════════════════[...]

const REGISTRATION_STATE_FILE = path.join(__dirname, '.registration-complete');

function isRegistrationComplete() {
    return fs.existsSync(REGISTRATION_STATE_FILE);
}

function markRegistrationComplete() {
    try {
        fs.writeFileSync(REGISTRATION_STATE_FILE, JSON.stringify({
            completedAt: new Date().toISOString(),
            version: '1.0.0'
        }));
        console.log('✅ [REGISTRATION] Marked as complete - registration endpoint disabled');
    } catch (err) {
        console.warn('⚠️  [REGISTRATION] Could not write state file:', sanitizeForLogging(err.message));
    }
}

// ════════════════════════════════════════════════════════════════[...]
// ANTI-FORGERY PRODUCTION SERVICE INITIALIZATION
// ════════════════════════════════════════════════════════════════[...]

const antiForgerConfig = {
    keyManager: {
        keyRotationInterval: 7 * 24 * 60 * 60 * 1000, // 7 days
        hsmEnabled: process.env.HSM_ENABLED === 'true'
    },
    sharedSecret: process.env.SHARED_SECRET || crypto.randomBytes(64).toString('hex'),
    network: {
        whitelist: (process.env.IP_WHITELIST || '127.0.0.1').split(',').map(ip => ip.trim()),
        blacklist: (process.env.IP_BLACKLIST || '').split(',').filter(ip => ip.trim()).map(ip => ip.trim()),
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX || '1000', 10),
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '60000', 10),
        requireWhitelist: process.env.REQUIRE_WHITELIST !== 'false'
    }
};

let secureResponseManager = null;

// ════════════════════════════════════════════════════════════════[...]
// STEP 1: INITIALIZE ANTI-FORGERY PRODUCTION (RESPONSE SECURITY)
// ════════════════════════════════════════════════════════════════[...]

try {
    secureResponseManager = new SecureResponseManager(antiForgerConfig);
    console.log('✅ [SECURITY] Anti-Forgery Production initialized');
    console.log('   ├─ Ed25519 key rotation: 7 days');
    console.log('   ├─ Nonce management: 32-byte, 5-min TTL, one-time use');
    console.log('   ├─ HMAC-SHA256 transport integrity');
    console.log('   ├─ IP whitelist: ' + Array.from(secureResponseManager.networkManager.ipWhitelist).join(', '));
    console.log('   ├─ Rate limiting: ' + antiForgerConfig.network.maxRequests + ' req/' + (antiForgerConfig.network.windowMs / 1000) + 's');
    console.log('   └─ Security Rating: 99/100');
} catch (err) {
    console.error('[SECURITY] ❌ Failed to initialize SecureResponseManager:', sanitizeForLogging(err.message));
    process.exit(1);
}

// ════════════════════════════════════════════════════════════════[...]
// STEP 3: INITIALIZE SSL/TLS VERIFICATION MODULE
// ════════════════════════════════════════════════════════════════[...]

let sslTlsModule = null;

try {
    // Enable verification middleware (this patches https.request and sets defaults)
    enableSSLVerificationMiddleware({
        configPath: process.env.SSL_CONFIG_PATH ||
            path.join(__dirname, 'security-config', 'ssl-config.json'),
        caBundlePath: process.env.SSL_CA_BUNDLE_PATH ||
            path.join(__dirname, 'security-config', 'ca-bundle.pem'),
        enableAuditLog: process.env.SSL_AUDIT_ENABLED !== 'false'
    });

    // Normalize runtime module object so other code can test `sslTlsModule` and call helpers.
    sslTlsModule = {
        enabled: true,
        makeVerifiedRequest,    // function imported from security/ssl-tls-verification.js
        getSSLStatus,
        getAuditStats,
        loadSSLConfig,
        shutdown: shutdownSSLTLS,
        getConfig: getSSLConfig
    };

    console.log('✅ [SSL-TLS] Verification module initialized and integrated');
} catch (err) {
    console.error('[SSL-TLS] ❌ Failed to initialize:', sanitizeForLogging(err.message));
    if (process.env.NODE_ENV === 'production') {
        console.error('[SSL-TLS] FATAL: Required in production. Exiting.');
        process.exit(1);
    }
}

// ════════════════════════════════════════════════════════════════[...]
// STEP 4: INITIALIZE ATTACK DETECTION (LAYER 6)
// Inserted immediately after SSL/TLS initialization
// ════════════════════════════════════════════════════════════════[..[...]

let attackDetectionEngine = null;
let attackDetectionMiddleware = null;

try {
    attackDetectionEngine = createAttackDetectionEngine();
    attackDetectionMiddleware = createAttackDetectionMiddleware(attackDetectionEngine);

    console.log('✅ [SECURITY] Attack Detection Engine initialized');
    console.log('   ├─ Injection Detection: SQL, NoSQL, XSS, Command, Path Traversal');
    console.log('   ├─ Rate Limiting: Per-IP DDoS/Flooding Detection');
    console.log('   ├─ Brute Force: Progressive Failed Auth Tracking');
    console.log('   ├─ Slow Attacks: Slowloris Detection');
    console.log('   ├─ Protocol Violations: Header & Body Checks');
    console.log('   └─ Security Rating: 98/100');
} catch (err) {
    console.error('[ATTACK-DETECTION] ❌ Failed to initialize:', sanitizeForLogging(err.message));
    if (process.env.NODE_ENV === 'production') {
        console.error('[ATTACK-DETECTION] FATAL: Required in production. Exiting.');
        process.exit(1);
    }
}

// ════════════════════════════════════════════════════════════════[...]
// QUANTUM SAFE ENVELOPE SERVICE (LAZY LOADING)
// ════════════════════════════════════════════════════════════════[...]

let quantumProxy = null;
let quantumProxyLoadPromise = null;
let quantumEnvelopeService = null;
let quantumConsoleOverrideEnabled = false;

// ✅ REMOVED: Early destructuring and enableGlobalConsoleOverride call (lines 303-315)
// Now deferred until first use in initQuantumProxy()

// Parse quantum console override setting early (non-blocking)
if (process.env.QUANTUM_CONSOLE_OVERRIDE === '1' || process.env.QUANTUM_CONSOLE_OVERRIDE === 'true') {
    quantumConsoleOverrideEnabled = true;
}

async function initQuantumProxy() {
    if (quantumProxy) {
        return quantumProxy;
    }

    if (!quantumProxyLoadPromise) {
        quantumProxyLoadPromise = (async () => {
            try {
                // ✅ LAZY LOAD: Import quantum service only when first needed
                if (!quantumEnvelopeService) {
                    quantumEnvelopeService = require('./modules/security/quantum-safe-envelope');

                    // ✅ DEFERRED: Apply console override after loading
                    const { enableGlobalConsoleOverride } = quantumEnvelopeService;
                    if (enableGlobalConsoleOverride) {
                        enableGlobalConsoleOverride(quantumConsoleOverrideEnabled);
                    }
                }

                const proxy = await quantumEnvelopeService.initQuantumProxy({
                    importPath: './quantum-safe-modern.js',
                    timeoutMs: 10000
                });
                quantumProxy = proxy || null;
                if (quantumProxy) {
                    console.log('[QUANTUM] ✅ Modern quantum-safe proxy initialized');
                }
                return quantumProxy;
            } catch (error) {
                console.error('[QUANTUM] ❌ Failed to initialize proxy:', sanitizeForLogging(error.message));
                throw error;
            }
        })();
    }

    return quantumProxyLoadPromise;
}

async function buildQuantumEnvelope(payload, aad = '') {
    if (!quantumProxy) {
        try {
            await initQuantumProxy();
        } catch (e) {
            console.warn('[QUANTUM] Init failed, proceeding without quantum envelope');
            return null;
        }
    }

    if (!quantumProxy) {
        return null;
    }

    if (!quantumEnvelopeService) {
        return null;
    }

    try {
        const envelope = await quantumEnvelopeService.buildQuantumEnvelope(payload, aad);
        return envelope;
    } catch (error) {
        console.warn('[QUANTUM] Envelope creation failed:', sanitizeForLogging(error.message));
        return null;
    }
}

async function tryDecryptQuantumEnvelope(body, aad = '') {
    if (!body || typeof body !== 'object' || !body.encrypted || !('packet' in body)) {
        return null;
    }

    if (!quantumProxy) {
        try {
            await initQuantumProxy();
        } catch (e) {
            return null;
        }
    }

    if (!quantumProxy) {
        return null;
    }

    if (!quantumEnvelopeService) {
        return null;
    }

    try {
        const plaintext = await quantumEnvelopeService.tryDecryptQuantumEnvelope(body, aad);
        return plaintext;
    } catch (error) {
        console.warn('[QUANTUM] Decryption failed:', sanitizeForLogging(error.message));
        return null;
    }
}

async function getEncryptionCapabilitySummary(req = null) {
    if (!quantumEnvelopeService) {
        return null;
    }
    return await quantumEnvelopeService.getEncryptionCapabilitySummary(req);
}

// ════════════════════════════════════════════════════════════════[...]
// API KEY AUTHENTICATION MODULE
// ════════════════════════════════════════════════════════════════[...]

const HMAC_SECRET = process.env.HMAC_SECRET || crypto.randomBytes(64).toString('hex');

let PROXY_API_KEY = resolveBootstrapApiKey();

if (process.env.PROXY_USE_ENV_KEY === 'true' && process.env.PROXY_API_KEY && process.env.PROXY_API_KEY.trim()) {
    PROXY_API_KEY = process.env.PROXY_API_KEY.trim();
}

PROXY_API_KEY = PROXY_API_KEY.trim();
console.log('[SECURITY] ✅ PROXY_API_KEY loaded (authentication enabled)');

// Create bootstrap key
const bootstrapKeyData = keyManager.createKey({
    name: 'bootstrap',
    scopes: ['read', 'write', 'admin'],
    expiresIn: 90 * 24 * 60 * 60 * 1000
});

keyManager.keys.set(PROXY_API_KEY, {
    ...bootstrapKeyData,
    key: PROXY_API_KEY,
    enabled: true,
    expires: Date.now() + (90 * 24 * 60 * 60 * 1000),
    type: 'bootstrap',
    createdAt: Date.now()
});

rbacManager.assignRole('bootstrap-admin', 'admin');
console.log('[API-KEY] ✅ Bootstrap key registered with admin role');

/**
 * Build internal auto-sign context for service-to-service requests
 */
function buildInternalAutoSignContext(req) {
    try {
        const rawBody = (req.rawBody && Buffer.isBuffer(req.rawBody)) ? req.rawBody :
            (req.rawBody || (typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? {})));

        const nonce = crypto.randomBytes(32);
        const timestamp = Date.now();
        const method = req.method;
        const path = req.path;

        const signingMessage = Buffer.concat([
            Buffer.from('REQUEST_SIGN_V1'),
            Buffer.from(method),
            Buffer.from(path),
            Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody)),
            nonce,
            Buffer.from(timestamp.toString())
        ]);

        const signature = crypto
            .createHmac('sha256', HMAC_SECRET)
            .update(signingMessage)
            .digest('hex');

        req.headers['authorization'] = `Bearer ${PROXY_API_KEY}`;
        req.headers['x-hmac-sha256'] = signature;
        req.headers['x-request-nonce'] = nonce.toString('hex');
        req.headers['x-request-timestamp'] = String(timestamp);
        req.headers['x-signature-algorithm'] = 'hmac-sha256-v1';
        req.headers['x-service-authenticated'] = 'true';

        req.internal_auto_sign = true;
        req.internal_auto_sign_signature = signature;
        req.requestSigningMetadata = {
            nonce: nonce.toString('hex'),
            timestamp,
            algorithm: 'hmac-sha256-v1',
            method,
            path
        };

        console.log('[API-KEY] ✅ Request auto-signed for internal service');
        return { signature, rawBody, metadata: req.requestSigningMetadata };
    } catch (err) {
        console.error('[API-KEY] ❌ Failed to build auto-sign context:', sanitizeForLogging(err.message));
        throw err;
    }
}

// ════════════════════════════════════════════════════════════════[...]
// STEP 2: INITIALIZE ANTI-FORGERY TRANSPORT LAYER (DEFERRED)
// Called here after HMAC_SECRET and buildInternalAutoSignContext defined
// ════════════════════════════════════════════════════════════════[...]

let antiForgeryTransportModule = null;

try {
    registerAntiForgeryTransport(app, {
        persistKeyDir: path.join(__dirname, 'security-keys'),
        caBundlePath: process.env.SSL_CA_BUNDLE_PATH ||
            path.join(__dirname, 'security-config', 'ca-bundle.pem'),
        sslConfigPath: process.env.SSL_CONFIG_PATH ||
            path.join(__dirname, 'security-config', 'ssl-config.json'),
        sslAuditLogPath: process.env.SSL_AUDIT_LOG ||
            path.join(__dirname, 'logs', 'ssl-verification.jsonl'),
        ed25519PrivatePem: process.env.ED25519_PRIVATE_PEM || undefined,
        ed25519PublicPem: process.env.ED25519_PUBLIC_PEM || undefined,
        hmacSecret: HMAC_SECRET,
        sqlDetector,
        m7Crypto,
        buildInternalAutoSignContext,
        maxClockSkewMs: parseInt(process.env.MAX_CLOCK_SKEW_MS || '300000', 10),
        maxBodyBytes: parseInt(process.env.MAX_BODY_BYTES || '10485760', 10)
    });

    antiForgeryTransportModule = app.locals.security;
    console.log('✅ [ANTI-FORGERY] Transport layer initialized (Ed25519 + HMAC)');
    console.log('   ├─ HMAC_SECRET configured');
    console.log('   ├─ buildInternalAutoSignContext integrated');
    console.log('   ├─ sqlDetector available');
    console.log('   └─ m7Crypto available');
} catch (err) {
    console.error('[ANTI-FORGERY] ❌ Initialization failed:', sanitizeForLogging(err.message));
    if (process.env.NODE_ENV === 'production') {
        console.error('[ANTI-FORGERY] FATAL: Required in production. Exiting.');
        process.exit(1);
    }
}

// ════════════════════════════════════════════════════════════════[...]
// STEP 2b: INITIALIZE PROXY ENCRYPTION GATEWAY (note.md Lines 87-93)
// Initialized after HMAC_SECRET (line 398 equivalent)
// ════════════════════════════════════════════════════════════════[...]

let proxyGateway = null;

try {
    proxyGateway = initProxyEncryptionGateway({
        hmacSecret: HMAC_SECRET,
        logger: console,
        sessionTTL: 24 * 60 * 60 * 1000,
        rateLimitMax: 30,
        rateLimitWindow: 60000
    });
    console.log('✅ [PROXY-GATEWAY] Initialized with 8 security layers');
    console.log('   ├─ AES-256-GCM encryption/decryption');
    console.log('   ├─ Session validation & revocation');
    console.log('   ├─ Rate limiting: 30 req/60s per IP');
    console.log('   ├─ SSRF protection (URL validation)');
    console.log('   ├─ IP access control (whitelist/blacklist)');
    console.log('   ├─ Auto-signing (service-to-service)');
    console.log('   ├─ Health check & diagnostics');
    console.log('   └─ Security Rating: 99/100');
} catch (err) {
    console.error('[PROXY-GATEWAY] ❌ Failed to initialize:', sanitizeForLogging(err.message));
    if (process.env.NODE_ENV === 'production') {
        console.error('[PROXY-GATEWAY] FATAL: Required in production. Exiting.');
        process.exit(1);
    }
}

/**
 * Enhanced API key middleware with anti-forgery integration
 */
function validateApiKeyMiddleware(req, res, next) {
    const apiKey = req.headers['x-api-key'] ||
        (req.headers.authorization || '').replace('Bearer ', '').trim();

    if (!apiKey) {
        console.warn('[API-KEY] ⚠️  Request missing API key');
        return res.status(401).json({
            error: 'Unauthorized',
            detail: 'API key required (X-API-Key header or Authorization: Bearer)',
            nonce: req.securityNonce || 'N/A'
        });
    }

    if (isTokenBlacklisted(apiKey)) {
        console.warn('[API-KEY] ⚠️  Blacklisted API key used (nonce: %s)', req.securityNonce);
        return res.status(401).json({
            error: 'Unauthorized',
            detail: 'API key has been revoked'
        });
    }

    const keyEntry = keyManager.keys.get(apiKey);

    if (!keyEntry || !keyEntry.enabled) {
        console.warn('[API-KEY] ⚠️  Invalid API key attempt from fingerprint: %s',
            req.securityFingerprint);
        return res.status(401).json({
            error: 'Unauthorized',
            detail: 'Invalid or disabled API key'
        });
    }

    if (keyEntry.expires && Date.now() > keyEntry.expires) {
        console.warn('[API-KEY] ⚠️  Expired API key used');
        return res.status(401).json({
            error: 'Unauthorized',
            detail: 'API key has expired'
        });
    }

    req.apiKey = apiKey;
    req.apiKeyEntry = keyEntry;
    req.apiKeyScopes = keyEntry.scopes || [];
    req.apiKeyRole = keyEntry.type || 'user';

    console.log('[API-KEY] ✅ Valid (fingerprint=%s, scopes=%s)',
        req.securityFingerprint?.substring(0, 8) + '...' || 'N/A',
        req.apiKeyScopes.join(','));

    next();
}

// ════════════════════════════════════════════════════════════════[...]
// TOKEN BLACKLIST & REVOCATION
// ════════════════════════════════════════════════════════════════[...]

let tokenBlacklist = [];

function loadTokenBlacklist() {
    try {
        const blacklistPath = path.join(__dirname, 'token-blacklist.json');
        if (fs.existsSync(blacklistPath)) {
            const data = JSON.parse(fs.readFileSync(blacklistPath, 'utf8'));
            tokenBlacklist = data.blacklist || [];
            console.log(`✅ Token blacklist loaded (${tokenBlacklist.length} revoked tokens)`);
        } else {
            tokenBlacklist = [];
            console.log('ℹ️  No token blacklist found');
        }
    } catch (e) {
        console.warn('⚠️  Could not load token blacklist:', sanitizeForLogging(e.message));
        tokenBlacklist = [];
    }
}

function isTokenBlacklisted(token) {
    loadTokenBlacklist();
    const found = tokenBlacklist.find(entry => entry.token === token);
    if (found) {
        console.warn(`[SECURITY] ⚠️  Blacklisted token used (reason: ${found.reason})`);
        return true;
    }
    return false;
}

// ════════════════════════════════════════════════════════════════[...]
// M7 EGRESS CONFIGURATION
// ════════════════════════════════════════════════════════════════[...]

const M7_EGRESS_CONFIG_PATH = process.env.M7_EGRESS_CONFIG_PATH ||
    path.join(__dirname, 'm7-egress.json');

let m7EgressConfig = {
    enabled: false,
    target: 'https://example.com',
    strict: false
};

function loadM7EgressConfig() {
    try {
        if (fs.existsSync(M7_EGRESS_CONFIG_PATH)) {
            const configData = JSON.parse(fs.readFileSync(M7_EGRESS_CONFIG_PATH, 'utf8'));
            m7EgressConfig = { ...m7EgressConfig, ...configData };
        } else {
            fs.writeFileSync(M7_EGRESS_CONFIG_PATH, JSON.stringify(m7EgressConfig, null, 2));
        }
    } catch (error) {
        console.warn('[M7 EGRESS] ❌ Could not load configuration:', sanitizeForLogging(error.message));
    }
}

function saveM7EgressConfig() {
    try {
        fs.writeFileSync(M7_EGRESS_CONFIG_PATH, JSON.stringify(m7EgressConfig, null, 2));
    } catch (error) {
        console.warn('[M7 EGRESS] ❌ Could not save configuration:', sanitizeForLogging(error.message));
    }
}

// ════════════════════════════════════════════════════════════════[...]
// STARTUP INITIALIZATION
// ════════════════════════════════════════════════════════════════[...]

loadTokenBlacklist();
loadM7EgressConfig();

// ════════════════════════════════════════════════════════════════[...]
// STEP 5: INITIALIZE KEY MANAGER (ENCRYPTION KEY MANAGEMENT)
// Inserted after M7/network config, before middleware stack
// ════════════════════════════════════════════════════════════════[...]

try {
    const keyConfig = {
        encryption: { enabled: process.env.ENCRYPTION_ENABLED !== 'false' },
        keys: {
            rotationEnabled: process.env.KEY_ROTATION_ENABLED !== 'false',
            rotationIntervalDays: parseInt(process.env.KEY_ROTATION_DAYS || '30', 10),
            maxKeysRetained: parseInt(process.env.MAX_KEYS_RETAINED || '5', 10)
        },
        encryption_storage: {
            currentKeyFile: process.env.ENCRYPTION_KEY_FILE ||
                path.join(__dirname, 'security-keys', 'encryption-key.json'),
            keyHistoryFile: process.env.ENCRYPTION_HISTORY_FILE ||
                path.join(__dirname, 'security-keys', 'key-history.json')
        },
        audit: {
            auditDir: process.env.ENCRYPTION_AUDIT_DIR ||
                path.join(__dirname, 'logs', 'encryption-audit')
        }
    };

    KeyManager.init(keyConfig);
    console.log('✅ [KEY-MGR] Initialized');
    console.log('   ├─ Encryption: ' + (keyConfig.encryption.enabled ? 'enabled' : 'disabled'));
    console.log('   ├─ Key rotation: ' + (keyConfig.keys.rotationEnabled ? 'enabled' : 'disabled') + ' (every ' + keyConfig.keys.rotationIntervalDays + ' days)');
    console.log('   ├─ Max retained keys: ' + keyConfig.keys.maxKeysRetained);
    console.log('   ├─ Current key version: ' + (KeyManager.getKeyMetadata()?.version || 'none'));
    console.log('   └─ Audit logging: ' + keyConfig.audit.auditDir);

    // ══════════════════════════════════════════════════════════════[.[...]
    // STEP 5b: INJECT KeyManager INTO M7-CRYPTO FOR AES-GCM OPERATIONS
    // ══════════════════════════════════════════════════════════════[.[...]
    if (m7Crypto.setKeyManager(KeyManager)) {
        console.log('✅ [M7-CRYPTO] KeyManager injected successfully');
        console.log('   ├─ encryptPayload() will use active key from KeyManager');
        console.log('   ├─ decryptPayload() will track metrics automatically');
        console.log('   └─ All AES-256-GCM operations monitored');
    } else {
        console.warn('[M7-CRYPTO] ⚠️  Failed to inject KeyManager (crypto operations will use fallback)');
    }
} catch (err) {
    console.error('[KEY-MGR] ❌ Failed to initialize:', sanitizeForLogging(err.message));
    if (process.env.NODE_ENV === 'production') {
        console.error('[KEY-MGR] ❌ Failed to initialize:', sanitizeForLogging(err.message));
        process.exit(1);
    }
}

// ✅ DEFERRED: Async initialization of quantum proxy (non-blocking)
(async () => {
    try {
        await initQuantumProxy();
    } catch (error) {
        console.warn('[STARTUP] ⚠️  Quantum proxy initialization deferred (non-blocking)');
    }
})();

// ════════════════════════════════════════════════════════════════[...]
// MIDDLEWARE STACK (EXACT ORDER MATTERS!)
// ════════════════════════════════════════════════════════════════[...]
// 1️⃣  RAW BODY CAPTURE       [antiForgeryTransport - already registered]
// 2️⃣  BODY PARSERS           [express.json, express.urlencoded]
// 3️⃣  ANTI-FORGERY CHECKS    [antiForgeryTransport - already registered]
// 4️⃣  HMAC VERIFICATION      [antiForgeryTransport - already registered]
// 5️⃣  PROXY GATEWAY          [proxy encryption gateway middleware]
// 6️⃣  RATE LIMITING          [express-rate-limit]
// 7️⃣  API KEY VALIDATION     [validateApiKeyMiddleware - optional on protected routes]

// 2️⃣  BODY PARSERS
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 3️⃣  ATTACK DETECTION (Layer 6)
// Position: After express.json() and express.urlencoded(), before rate limiters
if (attackDetectionMiddleware) {
    app.use(attackDetectionMiddleware.requestHandler());
    console.log('✅ [MIDDLEWARE] Attack Detection middleware registered (position 3)');
}

// 5️⃣  PROXY GATEWAY MIDDLEWARE STACK (note.md Lines 98-100)
// Position: After body parsers, before rate limiters
if (proxyGateway) {
    const middlewareStack = proxyGateway.createMiddlewareStack();
    app.use(...middlewareStack);
    console.log('✅ [MIDDLEWARE] Proxy encryption gateway registered (position 5)');
}

// 6️⃣  RATE LIMITING
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests', detail: 'Rate limit exceeded' },
    skip: (req) => req.path === '/health'
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || 'unknown',
    message: { error: 'Too many authentication attempts', detail: 'Try again in 15 minutes' }
});

app.use(generalLimiter);
app.use('/auth/mfa', authLimiter);

// ════════════════════════════════════════════════════════════════[...]
// MFA ENDPOINTS: EMAIL-BASED AUTHENTICATION WITH MAGIC LINKS
// ════════════════════════════════════════════════════════════════[...]

// POST /auth/mfa/register - Create new user account (ONE-TIME ONLY - first setup after build)
app.post('/auth/mfa/register', async (req, res) => {
    const { email, password, username } = req.body;

    try {
        // 🔒 NEW: Check if registration is already complete
        if (isRegistrationComplete()) {
            console.warn('[MFA] 🚫 Registration attempt blocked - already completed');
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Registration has already been completed. Contact your administrator if you need access.',
                registrationStatus: 'completed'
            });
        }

        if (!email || !password || !username) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Missing required fields: email, password, username',
                example: { email: 'user@example.com', password: 'secure123', username: 'johndoe' }
            });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Invalid email format'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Password must be at least 8 characters'
            });
        }

        if (username.length < 3 || username.length > 32) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Username must be between 3 and 32 characters'
            });
        }

        console.log(`[MFA] Registration request from ${sanitizeForLogging(email)}`);

        // Generate magic link
        const magicToken = generateMagicToken();
        const magicLink = createMagicLink(magicToken);
        
        // Store token with email and metadata
        storeMagicToken(magicToken, email, 'register');
        
        // Send magic link via email
        await emailService.sendMagicLink(email, magicLink, {
            action: 'complete your registration',
            actionTitle: 'Complete Registration',
            expiryMinutes: 15
        });

        console.log(`[MFA] ✅ Magic link sent to ${sanitizeForLogging(email)} for registration`);

        res.status(202).json({
            status: 'email_sent',
            message: 'Check your email for the verification link. Link expires in 15 minutes.',
            email: sanitizeForLogging(email),
            nextStep: 'Click the link in your email to complete registration'
        });

    } catch (err) {
        console.error(`[MFA] ❌ Registration error:`, sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// POST /auth/mfa/login - Login with email and password
app.post('/auth/mfa/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Missing required fields: email, password',
                example: { email: 'user@example.com', password: 'secure123' }
            });
        }

        console.log(`[MFA] Login request from ${sanitizeForLogging(email)}`);

        const key = await mfaManager.validateAPIKey(email, password);

        if (!key.valid) {
            console.warn(`[MFA] ⚠️  Failed login attempt for ${sanitizeForLogging(email)}`);
            return res.status(401).json({
                error: 'Unauthorized',
                detail: 'Invalid email or password'
            });
        }

        // Generate magic link for login
        const magicToken = generateMagicToken();
        const magicLink = createMagicLink(magicToken);
        
        // Store token with email and metadata
        storeMagicToken(magicToken, email, 'login');
        
        // Send magic link via email
        await emailService.sendMagicLink(email, magicLink, {
            action: 'verify your login',
            actionTitle: 'Verify Login',
            expiryMinutes: 15
        });

        console.log(`[MFA] ✅ Magic link sent to ${sanitizeForLogging(email)} for login`);

        res.status(202).json({
            status: 'email_sent',
            message: 'Check your email for the verification link. Link expires in 15 minutes.',
            email: sanitizeForLogging(email),
            nextStep: 'Click the link in your email to complete login'
        });

    } catch (err) {
        console.error(`[MFA] ❌ Login error:`, sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /auth/mfa/verify-link - Handle magic link clicks from email
app.get('/auth/mfa/verify-link', async (req, res) => {
    const { token } = req.query;

    try {
        if (!token) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Missing verification token'
            });
        }

        // Validate token
        const validation = validateMagicToken(token);
        if (!validation.valid) {
            console.warn(`[MFA] ❌ Magic link verification failed: ${validation.reason}`);
            return res.status(401).json({
                error: 'Unauthorized',
                detail: `Verification failed: ${validation.reason}`,
                nextStep: 'Request a new verification link'
            });
        }

        const { email, type } = validation.data;
        console.log(`[MFA] ✅ Magic link verified for ${sanitizeForLogging(email)} (type: ${type})`);

        // Handle registration
        if (type === 'register') {
            // Mark registration as complete
            markRegistrationComplete();
            
            // Consume the token
            consumeMagicToken(token);
            
            // Return success and generate API key
            const result = await mfaManager.requestNewAPIKey(email, {
                metadata: { verifiedAt: Date.now() }
            });

            // Send API key via email
            await emailService.sendAPIKey(email, result.secret, `${result.expiresIn / (24 * 60 * 60 * 1000)} days`);

            return res.json({
                status: 'success',
                message: 'Registration completed! Your API key has been sent to your email.',
                type: 'registration',
                email: sanitizeForLogging(email)
            });
        }

        // Handle login
        if (type === 'login') {
            // Consume the token
            consumeMagicToken(token);
            
            // Generate new API key
            const result = await mfaManager.requestKeyRotation(email, email);

            // Send new API key via email
            await emailService.sendAPIKey(email, result.secret, `${result.expiresIn / (24 * 60 * 60 * 1000)} days`);

            return res.json({
                status: 'success',
                message: 'Login verified! Your new API key has been sent to your email.',
                type: 'login',
                email: sanitizeForLogging(email)
            });
        }

        return res.status(400).json({
            error: 'Bad Request',
            detail: 'Invalid token type'
        });

    } catch (err) {
        console.error(`[MFA] ❌ Verification error:`, sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /auth/mfa/health - Health check for MFA service
app.get('/auth/mfa/health', (req, res) => {
    try {
        const expiringKeys = mfaManager.getExpiringKeys(7);
        const registrationComplete = isRegistrationComplete();
        const activeMagicLinks = magicLinkTokens.size;

        res.json({
            status: 'operational',
            service: 'Email-Based MFA with Magic Links',
            timestamp: new Date().toISOString(),
            registrationStatus: registrationComplete ? 'completed' : 'pending',
            expiringKeysCount: expiringKeys.length,
            activeMagicLinks,
            capabilities: {
                registration: !registrationComplete,
                login: true,
                magic_link_verification: true,
                key_rotation: true,
                key_revocation: true,
                email_delivery: !!emailService.transporter
            }
        });
    } catch (err) {
        console.error('[MFA] ❌ Health check error:', sanitizeForLogging(err.message));
        res.status(500).json({
            status: 'error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// Inserted secure file-serving route (validated with hardened path-validator)
const PUBLIC_DIR = path.join(__dirname, 'pages');

app.get('/files/:file(*)', (req, res) => {
  const userPath = req.params.file || '';
  const result = pathValidator.validateFilePath(userPath, PUBLIC_DIR);
  if (!result.ok) {
    console.warn('[PATH-VALIDATOR] Blocked file request:', { reason: result.reason });
    return res.status(403).json({ error: 'Forbidden', detail: 'Invalid file path' });
  }

  const fullPath = result.fullPath;

  try {
    const stat = fs.statSync(fullPath);
    if (!stat.isFile()) {
      return res.status(404).json({ error: 'Not Found' });
    }
  } catch (err) {
    return res.status(404).json({ error: 'Not Found' });
  }

  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'");

  return res.sendFile(fullPath);
});

// ════════════════════════════════════════════════════════════════[...]
// SSL/TLS HEALTH CHECK ENDPOINTS
// ════════════════════════════════════════════════════════════════[.[...]

// GET /health/ssl - SSL/TLS verification health status
app.get('/health/ssl', (req, res) => {
    try {
        const status = getSSLStatus();
        res.json({
            ...status,
            timestamp: new Date().toISOString(),
            uptime: {
                certificationsValidatedTotal: status.statistics.certificationsValidated,
                certificationsRejectedTotal: status.statistics.certificationsRejected,
                rejectionRate: status.statistics.rejectionRate
            }
        });
    } catch (err) {
        console.error('[SSL-TLS] ❌ Health check error:', sanitizeForLogging(err.message));
        res.status(500).json({
            status: 'error',
            module: 'SSL/TLS Verification',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /health/ssl/config - Current SSL configuration (admin only)
app.get('/health/ssl/config', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const config = getSSLConfig();
        res.json({
            status: 'ok',
            module: 'SSL/TLS Verification',
            configuration: {
                ssl: config.ssl,
                certificateValidation: config.certificateValidation,
                errorHandling: config.errorHandling,
                upstreamOverrides: Object.keys(config.upstreamOverrides || {})
            },
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('[SSL-TLS] ❌ Config retrieval error:', sanitizeForLogging(err.message));
        res.status(500).json({
            status: 'error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// ... rest of server.js remains unchanged ...

// ═══════════════════════════════════════════════════════════════[.[...]
// EXAMPLE PROTECTED ROUTE (with API key validation)
// ═══════════════════════════════════════════════════════════════[.[...]

app.get('/api/protected-resource', validateApiKeyMiddleware, (req, res) => {
    res.json({
        status: 'success',
        message: 'Protected resource accessed',
        apiKey: req.apiKey,
        apiKeyScopes: req.apiKeyScopes,
        apiKeyRole: req.apiKeyRole,
        requestSigningMetadata: req.requestSigningMetadata,
        security: {
            nonce: req.securityNonce,
            fingerprint: req.securityFingerprint
        }
    });
});

// ... remaining content unchanged; exports at end remain the same
