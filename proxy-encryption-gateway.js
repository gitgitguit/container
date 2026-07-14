/**
 * ════════════════════════════════════════════════════════════════──[...]
 * PROXY ENCRYPTION GATEWAY MODULE
 * ════════════════════════════════════════════════════════════════──[...]
 * 
 * Production-grade security module for encrypted proxy sessions.
 * Provides AES-256-GCM encryption, rate limiting, session management,
 * and auto-signing for service-to-service requests.
 * 
 * Designed specifically for git050225/container server.js
 * 
 * DEPENDENCIES:
 * - crypto (Node.js built-in)
 * - HMAC_SECRET from server.js
 * - m7Crypto from server.js
 * - sqlDetector from server.js
 * 
 * ════════════════════════════════════════════════════════════════─[...]
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * ════════════════════════════════════════════════════════════════─[...]
 * SECTION 1: ENCRYPTION & DECRYPTION (AES-256-GCM)
 * ════════════════════════════════════════════════════════════════─[...]
 */

class ProxyEncryptionGateway {
    constructor(options = {}) {
        // ✅ HMAC_SECRET must be provided from server.js
        if (!options.hmacSecret) {
            throw new Error('[ProxyEncryptionGateway] FATAL: hmacSecret required');
        }

        this.hmacSecret = options.hmacSecret;
        this.logger = options.logger || console;

        // ✅ Derive AES-256 key from HMAC_SECRET
        this.aesKey = crypto
            .createHash('sha256')
            .update(this.hmacSecret)
            .digest();

        // ✅ Session management
        this.sessionStore = new Map(); // In-memory default
        this.sessionTTL = options.sessionTTL || (24 * 60 * 60 * 1000); // 24 hours
        this.revokedTokens = new Map(); // Token blacklist with timestamps

        // ✅ Rate limiting
        this.requestCounts = new Map();
        this.rateLimitWindow = options.rateLimitWindow || 60000; // 1 minute
        this.rateLimitMax = options.rateLimitMax || 30; // 30 req/min per IP

        // ✅ Configuration
        this.cookieSecure = options.cookieSecure !== undefined
            ? options.cookieSecure
            : process.env.NODE_ENV === 'production';

        this.cookieSameSite = options.cookieSameSite || 'lax';
        this.cookieHttpOnly = true; // Always true for security

        // ✅ IP policy configuration
        this.ipPolicyCachePath = options.ipPolicyCachePath ||
            path.join(process.cwd(), 'network-config.json');

        this.ipPolicyReloadInterval = options.ipPolicyReloadInterval || 30000; // 30s
        this.ipPolicy = null;
        this.ipPolicyLastLoaded = 0;

        // ✅ Revoked token cleanup configuration
        this.maxRevokeCacheTTL = options.maxRevokeCacheTTL || (7 * 24 * 60 * 60 * 1000); // 7 days
        this.cleanupInterval = options.cleanupInterval || (60 * 60 * 1000); // 1 hour
        this.startCleanupTimer();

        // ✅ PROXY_SECRET from environment
        if (!process.env.PROXY_SECRET || process.env.PROXY_SECRET.trim() === '') {
            const generatedSecret = crypto.randomBytes(32).toString('base64');
            process.env.PROXY_SECRET = generatedSecret;
            this.logger.warn('[ProxyEncryptionGateway] ⚠️  Auto-generated PROXY_SECRET (should be set in .env)');
        }

        this.proxySecret = process.env.PROXY_SECRET;
        this.logger.log('✅ [ProxyEncryptionGateway] Initialized (AES-256-GCM encryption enabled)');
    }

    /**
     * ═══════════════════════════════════════════════════════════════[...]
     * ENCRYPTION: Encrypt target URL with AES-256-GCM + expiry
     * ═══════════════════════════════════════════════════════════════[...]
     */
    encrypt(plaintext, expiryMs = this.sessionTTL) {
        try {
            const data = JSON.stringify({
                target: plaintext,
                expires: Date.now() + expiryMs,
                sessionId: crypto.randomUUID()
            });

            const iv = crypto.randomBytes(12); // 96-bit IV for GCM
            const cipher = crypto.createCipheriv('aes-256-gcm', this.aesKey, iv);

            let encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const authTag = cipher.getAuthTag();
            const token = `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;

            this.logger.log(`[Encrypt] ✅ Encrypted: ${plaintext.substring(0, 30)}...`);
            return token;
        } catch (err) {
            this.logger.error('[Encrypt] ❌ Error:', err.message);
            throw new Error(`Encryption failed: ${err.message}`);
        }
    }

    /**
     * ══════════════════════════════════════════════════════════════──[...]
     * DECRYPTION: Decrypt token with expiry validation + backward compatibility
     * ══════════════════════════════════════════════════════════════──[...]
     */
    decrypt(encryptedToken) {
        try {
            const [ivHex, encHex, tagHex] = encryptedToken.split(':');

            if (!ivHex || !encHex || !tagHex) {
                throw new Error('Invalid token format');
            }

            const decipher = crypto.createDecipheriv(
                'aes-256-gcm',
                this.aesKey,
                Buffer.from(ivHex, 'hex')
            );

            decipher.setAuthTag(Buffer.from(tagHex, 'hex'));

            let decrypted = decipher.update(encHex, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            // ✅ Try parsing as new JSON format with expiry
            try {
                const parsed = JSON.parse(decrypted);

                // ✅ Check expiry
                if (parsed.expires && Date.now() > parsed.expires) {
                    this.logger.warn('[Decrypt] ⚠️  Session expired');
                    return null;
                }

                // ✅ Check if token is revoked
                if (this.revokedTokens.has(encryptedToken)) {
                    this.logger.warn('[Decrypt] ⚠️  Token is revoked/blacklisted');
                    return null;
                }

                this.logger.log(`[Decrypt] ✅ Decrypted: ${parsed.target.substring(0, 30)}...`);
                return parsed.target;
            } catch (jsonErr) {
                // ✅ Fallback to legacy plain text format (backward compatibility)
                this.logger.warn('[Decrypt] ⚠️  Using legacy token format (no expiry)');
                return decrypted;
            }
        } catch (err) {
            this.logger.error('[Decrypt] ❌ Error:', err.message);
            return null;
        }
    }

    /**
     * ══════════════════════════════════════════════════════════════──[...]
     * SECTION 2: SESSION MANAGEMENT
     * ══════════════════════════════════════════════════════════════──[...]
     */

    /**
     * Validate session: Check expiry, revocation, and freshness
     */
    validateSession(token) {
        try {
            // ✅ Check blacklist
            if (this.revokedTokens.has(token)) {
                return {
                    valid: false,
                    reason: 'Token revoked/blacklisted',
                    code: 'REVOKED'
                };
            }

            // ✅ Decrypt and validate
            const plaintext = this.decrypt(token);
            if (!plaintext) {
                return {
                    valid: false,
                    reason: 'Decryption failed or token expired',
                    code: 'INVALID_OR_EXPIRED'
                };
            }

            return {
                valid: true,
                target: plaintext,
                code: 'OK'
            };
        } catch (err) {
            this.logger.error('[ValidateSession] ❌ Error:', err.message);
            return {
                valid: false,
                reason: err.message,
                code: 'ERROR'
            };
        }
    }

    /**
     * Revoke session token (add to blacklist with timestamp)
     */
    revokeSession(token) {
        try {
            this.revokedTokens.set(token, Date.now());
            this.logger.log('[RevokeSession] ✅ Token revoked');
            return { success: true };
        } catch (err) {
            this.logger.error('[RevokeSession] ❌ Error:', err.message);
            return { success: false, error: err.message };
        }
    }

    /**
     * Start automatic cleanup timer for revoked tokens
     */
    startCleanupTimer() {
        this.cleanupTimer = setInterval(() => {
            this.cleanupRevokedTokens();
        }, this.cleanupInterval);

        // Allow timer to be cleared on process exit
        if (this.cleanupTimer.unref) {
            this.cleanupTimer.unref();
        }
    }

    /**
     * Clear expired revoked tokens (maintenance)
     * ✅ FIXED: Now tracks revoke time and cleans up old entries
     */
    cleanupRevokedTokens() {
        try {
            const now = Date.now();
            let removed = 0;

            for (const [token, revokeTime] of this.revokedTokens.entries()) {
                if (now - revokeTime > this.maxRevokeCacheTTL) {
                    this.revokedTokens.delete(token);
                    removed++;
                }
            }

            this.logger.log(`[Cleanup] ✅ Revoked tokens cleaned: ${this.revokedTokens.size} remaining (removed ${removed})`);
        } catch (err) {
            this.logger.error('[Cleanup] ❌ Error:', err.message);
        }
    }

    /**
     * Manually trigger cleanup
     */
    manualCleanup() {
        this.cleanupRevokedTokens();
    }

    /**
     * Stop cleanup timer (e.g., on server shutdown)
     */
    stopCleanupTimer() {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.logger.log('[Cleanup] Timer stopped');
        }
    }

    /**
     * ══════════════════════════════════════════════════════════════──[...]
     * SECTION 3: RATE LIMITING (Per IP)
     * ══════════════════════════════════════════════════════════════──[...]
     */

    /**
     * Rate limiting middleware factory
     */
    rateLimitMiddleware() {
        return (req, res, next) => {
            const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
            const now = Date.now();

            // ✅ Initialize request tracking for this IP
            if (!this.requestCounts.has(clientIP)) {
                this.requestCounts.set(clientIP, []);
            }

            const requests = this.requestCounts.get(clientIP);
            const recentRequests = requests.filter(time => now - time < this.rateLimitWindow);

            // ✅ Check limit
            if (recentRequests.length >= this.rateLimitMax) {
                this.logger.warn(`[RateLimit] 🚫 Limit exceeded for ${clientIP}: ${recentRequests.length}/${this.rateLimitMax}`);
                return res.status(429).json({
                    error: 'Too many requests',
                    detail: `Rate limit: ${this.rateLimitMax} requests per ${this.rateLimitWindow / 1000}s`,
                    retryAfter: Math.ceil(this.rateLimitWindow / 1000)
                });
            }

            // ✅ Record this request
            recentRequests.push(now);
            this.requestCounts.set(clientIP, recentRequests);

            // ✅ Attach rate limit info to request
            req.rateLimit = {
                remaining: this.rateLimitMax - recentRequests.length,
                total: this.rateLimitMax,
                windowMs: this.rateLimitWindow
            };

            next();
        };
    }

    /**
     * Get rate limit stats for debugging
     */
    getRateLimitStats() {
        const stats = {};
        for (const [ip, requests] of this.requestCounts.entries()) {
            const now = Date.now();
            const recent = requests.filter(t => now - t < this.rateLimitWindow);
            stats[ip] = {
                requests: recent.length,
                limit: this.rateLimitMax,
                percentUsed: Math.round((recent.length / this.rateLimitMax) * 100)
            };
        }
        return stats;
    }

    /**
     * ══════════════════════════════════════════════════════════════──[...]
     * SECTION 4: INPUT VALIDATION
     * ══════════════════════════════════════════════════════════════──[...]
     */

    /**
     * Validate target URL for SSRF, malicious domains, etc.
     */
    validateProxyTarget(targetInput) {
        try {
            let target = targetInput?.trim();

            if (!target) {
                return {
                    valid: false,
                    reason: 'Target URL required'
                };
            }

            // ✅ Auto-prepend https:// if missing
            if (!target.startsWith('http://') && !target.startsWith('https://')) {
                target = 'https://' + target;
            }

            // ✅ Parse and validate URL
            const url = new URL(target);

            // ✅ Block private networks (SSRF protection)
            const privatePatterns = [
                /^localhost$/i,
                /^127\./,
                /^192\.168\./,
                /^10\./,
                /^172\.(1[6-9]|2[0-9]|3[01])\./,
                /^::1$/,
                /^fc00:/i,
                /^fe80:/i, // Link-local
                /^169\.254\./ // APIPA
            ];

            if (privatePatterns.some(p => p.test(url.hostname))) {
                return {
                    valid: false,
                    reason: 'Private networks blocked for security',
                    code: 'SSRF_BLOCKED'
                };
            }

            // ✅ Block malicious TLDs
            const blockedTLDs = ['.local', '.internal', '.test', '.localhost', '.invalid'];
            if (blockedTLDs.some(tld => url.hostname.endsWith(tld))) {
                return {
                    valid: false,
                    reason: 'Invalid domain TLD',
                    code: 'INVALID_TLD'
                };
            }

            // ✅ Block URLs with suspicious characters
            if (/[<>'"{}|\\^`]/.test(target)) {
                return {
                    valid: false,
                    reason: 'URL contains invalid characters',
                    code: 'INVALID_CHARS'
                };
            }

            this.logger.log(`[ValidateTarget] ✅ Valid target: ${url.hostname}`);
            return {
                valid: true,
                target,
                url,
                hostname: url.hostname,
                protocol: url.protocol,
                port: url.port || (url.protocol === 'https:' ? 443 : 80)
            };
        } catch (err) {
            this.logger.error('[ValidateTarget] ❌ Error:', err.message);
            return {
                valid: false,
                reason: `Invalid URL format: ${err.message}`,
                code: 'PARSE_ERROR'
            };
        }
    }

    /**
     * ══════════════════════════════════════════════════════════════──[...]
     * SECTION 5: IP ACCESS CONTROL
     * ══════════════════════════════════════════════════════════════──[...]
     */

    /**
     * Load IP policy from JSON file (with caching)
     */
    loadIPPolicy() {
        try {
            const now = Date.now();

            // ✅ Cache for 30 seconds to avoid excessive file reads
            if (this.ipPolicy && (now - this.ipPolicyLastLoaded) < this.ipPolicyReloadInterval) {
                return this.ipPolicy;
            }

            if (!fs.existsSync(this.ipPolicyCachePath)) {
                this.logger.warn(`[IPPolicy] ⚠️  Policy file not found: ${this.ipPolicyCachePath}`);
                return null;
            }

            const data = fs.readFileSync(this.ipPolicyCachePath, 'utf8');
            this.ipPolicy = JSON.parse(data);
            this.ipPolicyLastLoaded = now;

            this.logger.log(`[IPPolicy] ✅ Loaded (profile: ${this.ipPolicy.current_profile})`);
            return this.ipPolicy;
        } catch (err) {
            this.logger.error('[IPPolicy] ❌ Load failed:', err.message);
            return null;
        }
    }

    /**
     * Reload IP policy immediately (bypass cache)
     */
    reloadIPPolicy() {
        this.ipPolicyLastLoaded = 0; // Force reload
        return this.loadIPPolicy();
    }

    /**
     * Check if client IP is allowed based on policy
     */
    checkIPAccess(clientIP) {
        try {
            const policy = this.loadIPPolicy();
            if (!policy) {
                this.logger.warn('[IPAccess] ⚠️  No policy loaded, allowing by default');
                return true;
            }

            const profile = policy.profiles[policy.current_profile];
            if (!profile || !profile.enabled) {
                this.logger.log('[IPAccess] Policy disabled, allowing');
                return true;
            }

            const { mode, ips } = profile;
            const isInList = ips.includes(clientIP);

            if (mode === 'whitelist') {
                const allowed = isInList;
                this.logger.log(`[IPAccess] Whitelist: ${clientIP} = ${allowed ? '✅' : '❌'}`);
                return allowed;
            } else if (mode === 'blacklist') {
                const allowed = !isInList;
                this.logger.log(`[IPAccess] Blacklist: ${clientIP} = ${allowed ? '✅' : '❌'}`);
                return allowed;
            }

            return true;
        } catch (err) {
            this.logger.error('[IPAccess] ❌ Error:', err.message);
            return true; // Fail open
        }
    }

    /**
     * IP access enforcement middleware
     */
    enforceIPPolicy() {
        return (req, res, next) => {
            const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
            const allowed = this.checkIPAccess(clientIP);

            if (!allowed) {
                const policy = this.loadIPPolicy();
                const profile = policy?.profiles[policy?.current_profile];

                this.logger.warn(`[IPPolicy] 🚫 Blocked: ${clientIP}`);
                return res.status(403).json({
                    error: 'Access denied by network policy',
                    profile: policy?.current_profile || 'unknown',
                    mode: profile?.mode || 'unknown',
                    clientIP
                });
            }

            next();
        };
    }

    /**
     * ══════════════════════════════════════════════════════════════──[...]
     * SECTION 6: AUTO-SIGNING FOR SERVICE-TO-SERVICE
     * ══════════════════════════════════════════════════════════════──[...]
     */

    /**
     * Build auto-signed request for internal services
     * Injects HMAC signature invisibly
     */
    buildAutoSignedRequest(req, apiKey, options = {}) {
        try {
            const rawBody = req.rawBody || JSON.stringify(req.body || {});

            // ✅ Compute HMAC-SHA256 signature
            const computedSignature = crypto
                .createHmac('sha256', this.hmacSecret)
                .update(rawBody)
                .digest('base64');

            // ✅ Inject credentials
            const signedHeaders = {
                ...req.headers,
                'authorization': `Bearer ${apiKey}`,
                'x-hmac-sha256': computedSignature,
                'x-service-authenticated': 'true',
                'x-internal-auto-sign': 'true',
                'x-service-name': options.serviceName || 'internal-service',
                'x-service-timestamp': Date.now().toString()
            };

            this.logger.log(`[AutoSign] ✅ Request auto-signed`);
            this.logger.log(`   ├─ Service: ${options.serviceName || 'unknown'}`);
            this.logger.log(`   ├─ Payload size: ${rawBody.length} bytes`);
            this.logger.log(`   └─ Signature: ${computedSignature.substring(0, 20)}...`);

            return {
                success: true,
                headers: signedHeaders,
                signature: computedSignature,
                body: rawBody,
                metadata: {
                    serviceName: options.serviceName,
                    timestamp: Date.now(),
                    algorithm: 'hmac-sha256-v1'
                }
            };
        } catch (err) {
            this.logger.error('[AutoSign] ❌ Error:', err.message);
            return {
                success: false,
                error: err.message
            };
        }
    }

    /**
     * Validate auto-signed request
     * ✅ FIXED: Now uses timing-safe comparison
     */
    validateAutoSignedRequest(req) {
        try {
            const signature = req.get('x-hmac-sha256');
            const isAutoSigned = req.get('x-service-authenticated') === 'true';

            if (!isAutoSigned || !signature) {
                return {
                    valid: false,
                    reason: 'Not an auto-signed request'
                };
            }

            const rawBody = req.rawBody || JSON.stringify(req.body || {});
            const expectedSignature = crypto
                .createHmac('sha256', this.hmacSecret)
                .update(rawBody)
                .digest('base64');

            // ✅ Use constant-time comparison to prevent timing attacks
            let valid = false;
            try {
                valid = crypto.timingSafeEqual(
                    Buffer.from(signature),
                    Buffer.from(expectedSignature)
                );
            } catch (err) {
                // Buffers have different lengths or another error occurred
                this.logger.debug('[ValidateAutoSign] Timing-safe comparison failed:', err.message);
                valid = false;
            }

            if (!valid) {
                this.logger.warn('[ValidateAutoSign] ⚠️  Signature mismatch');
                return {
                    valid: false,
                    reason: 'Signature verification failed'
                };
            }

            this.logger.log('[ValidateAutoSign] ✅ Signature valid');
            return {
                valid: true,
                serviceName: req.get('x-service-name'),
                timestamp: req.get('x-service-timestamp')
            };
        } catch (err) {
            this.logger.error('[ValidateAutoSign] ❌ Error:', err.message);
            return {
                valid: false,
                reason: err.message
            };
        }
    }

    /**
     * ══════════════════════════════════════════════════════════════──[...]
     * SECTION 7: MIDDLEWARE FACTORY METHODS
     * ══════════════════════════════════════════════════════════════──[...]
     */

    /**
     * Create combined middleware stack
     */
    createMiddlewareStack() {
        return [
            this.rateLimitMiddleware(),
            this.enforceIPPolicy()
        ];
    }

    /**
     * Cookie settings factory
     */
    getCookieOptions() {
        return {
            httpOnly: this.cookieHttpOnly,
            secure: this.cookieSecure,
            sameSite: this.cookieSameSite,
            maxAge: this.sessionTTL
        };
    }

    /**
     * ═══════════──═════════════════════════════════════════════════──[...]
     * SECTION 8: HEALTH & DIAGNOSTICS
     * ══════════════════════════════════════════════════════════════──[...]
     */

    getStatus() {
        return {
            status: 'operational',
            module: 'ProxyEncryptionGateway',
            timestamp: new Date().toISOString(),
            configuration: {
                encryptionAlgorithm: 'aes-256-gcm',
                sessionTTL: this.sessionTTL,
                rateLimitMax: this.rateLimitMax,
                rateLimitWindow: this.rateLimitWindow,
                cookieSecure: this.cookieSecure,
                cookieSameSite: this.cookieSameSite,
                revokedTokenCleanupTTL: this.maxRevokeCacheTTL,
                cleanupInterval: this.cleanupInterval
            },
            statistics: {
                activeRateLimitedIPs: this.requestCounts.size,
                revokedTokens: this.revokedTokens.size,
                rateLimitStats: this.getRateLimitStats()
            }
        };
    }

    /**
     * Health check endpoint data
     */
    getHealthCheck() {
        try {
            const ipPolicy = this.loadIPPolicy();
            return {
                encryption: '✅ AES-256-GCM',
                rateLimit: `✅ ${this.rateLimitMax} req/${this.rateLimitWindow / 1000}s`,
                sessionTTL: `✅ ${this.sessionTTL / 3600000} hours`,
                ipPolicy: ipPolicy ? `✅ ${ipPolicy.current_profile}` : '⚠️  Not loaded',
                proxySecret: process.env.PROXY_SECRET ? '✅ Set' : '❌ Missing',
                revokedTokenCleanup: `✅ Active (TTL: ${this.maxRevokeCacheTTL / 3600000}h)`
            };
        } catch (err) {
            return {
                error: 'Health check failed',
                detail: err.message
            };
        }
    }
}

/**
 * ════════════════════════════════════════════════════════════════[...]
 * EXPORTS: Factory & Module Interface
 * ════════════════════════════════════════════════════════════════[...]
 */

/**
 * Initialize and return singleton instance
 */
function initProxyEncryptionGateway(options = {}) {
    return new ProxyEncryptionGateway(options);
}

module.exports = {
    ProxyEncryptionGateway,
    initProxyEncryptionGateway
};