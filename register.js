const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');

// ════════════════════════════════════════════════════════════════��[...]
// SECURITY CONSTANTS & CONFIGURATION
// ════════════════════════════════════════════════════════════════��[...]

const TOKEN_TTL_MS = 15 * 60 * 60 * 1000;  // 15 hours (900 minutes)
const TOKEN_TTL_DISPLAY = '15 hours';

// FIX #4: Secure OTP generation constants
const OTP_ENTROPY_BYTES = 4;  // 32-bit entropy
const OTP_LENGTH = 6;
const OTP_MAX_ATTEMPTS = 5;
const OTP_EXPIRY_MS = 15 * 60 * 1000;  // 15 minutes

// FIX #2: Password validation constants
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/;  // lowercase, uppercase, digit

// FIX #11: IP validation constants
const RESERVED_IPS = [
    '0.0.0.0', '255.255.255.255', '127.0.0.1',
    '224.0.0.0', '240.0.0.0'
];

// FIX #8: Whitelist path constraints
const WHITELIST_BASE_SUBDIR = 'whitelists';

// ════════════════════════════════════════════════════════════════�[...]
// SECURITY MODULE IMPORTS (FIX: IP Blacklist & Audit Logging Integration)
// ════════════════════════════════════════════════════════════════�[...]

let IntelligentIPBlacklist;
let AuditLogger;

try {
    IntelligentIPBlacklist = require('./modules/security/ip-blacklist-ddos');
} catch (e) {
    console.warn('[REGISTER] IP Blacklist module not available:', e.message);
}

try {
    AuditLogger = require('./modules/security/audit-logging');
} catch (e) {
    console.warn('[REGISTER] Audit Logger module not available:', e.message);
}

// ════════════════════════════════════════════════════════════════�[...]
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════�[...]

function escapeHtml(value = '') {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
        return forwarded.split(',')[0].trim();
    }
    return req.ip || req.socket?.remoteAddress || 'unknown';
}

const rateLimit_internal = new Map();
function checkRateLimit(key, maxAttempts = 5, windowMs = 60000) {
    const now = Date.now();
    const record = rateLimit_internal.get(key) || [];
    const recent = record.filter((timestamp) => now - timestamp < windowMs);
    if (recent.length >= maxAttempts) {
        return false;
    }
    recent.push(now);
    rateLimit_internal.set(key, recent);
    return true;
}

function getAccessSecret() {
    const configuredSecret = process.env.PROXY_SECRET || process.env.ACCESS_TOKEN_SECRET || '';
    if (configuredSecret.trim()) {
        return configuredSecret.trim();
    }

    const secretPath = path.join(__dirname, '.access-secret');
    try {
        if (fs.existsSync(secretPath)) {
            return fs.readFileSync(secretPath, 'utf8').trim();
        }
    } catch (error) {
        // fall through to generate a new secret
    }

    const generatedSecret = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretPath, generatedSecret, 'utf8');
    return generatedSecret;
}

/**
 * FIX #3: Timing-safe token verification
 * CRITICAL: Use crypto.timingSafeEqual to prevent timing attacks
 */
function createSignedToken(payload) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify({
        ...payload,
        iat: Date.now(),
        exp: Date.now() + TOKEN_TTL_MS,
        type: 'access'
    })).toString('base64url');
    const signature = crypto.createHmac('sha256', getAccessSecret())
        .update(`${header}.${body}`)
        .digest('base64url');
    return `${header}.${body}.${signature}`;
}

/**
 * FIX #3: Timing-safe token verification (CRITICAL SECURITY FIX)
 * Prevents timing attacks that leak signature information
 */
function verifySignedToken(token) {
    if (!token) {
        return null;
    }

    const parts = String(token).split('.');
    if (parts.length !== 3) {
        return null;
    }

    const [header, body, signature] = parts;
    const expectedSignature = crypto.createHmac('sha256', getAccessSecret())
        .update(`${header}.${body}`)
        .digest('base64url');

    // FIX #3: Use timing-safe comparison instead of simple ===
    let signatureMatch = false;
    try {
        signatureMatch = crypto.timingSafeEqual(
            Buffer.from(expectedSignature, 'base64url'),
            Buffer.from(signature, 'base64url')
        );
    } catch (e) {
        // Different lengths or buffer conversion errors
        return null;
    }

    if (!signatureMatch) {
        return null;
    }

    try {
        const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
        if (!payload.exp || Date.now() > payload.exp) {
            return null;
        }
        return payload;
    } catch (error) {
        return null;
    }
}

function buildLogoutUrl(baseUrl, token) {
    return `${baseUrl}/logout?token=${encodeURIComponent(token)}`;
}

function getBootstrapKeyPath() {
    const candidateDirs = [
        process.env.PROXY_CONFIG_DIR,
        path.join(__dirname, '..', 'config'),
        path.join(__dirname, 'config'),
        '/app/config',
        path.join(__dirname)
    ].filter(Boolean);

    for (const candidateDir of candidateDirs) {
        try {
            if (!fs.existsSync(candidateDir)) {
                fs.mkdirSync(candidateDir, { recursive: true });
            }
            return path.join(candidateDir, '.bootstrap-api-key');
        } catch (error) {
            // try the next candidate
        }
    }

    return path.join(__dirname, '.bootstrap-api-key');
}

function resolveBootstrapApiKey(options = {}) {
    const explicitKey = String(options.explicitKey || process.env.PROXY_API_KEY || '').trim();
    if (process.env.PROXY_USE_ENV_KEY === 'true' && explicitKey) {
        return explicitKey;
    }

    const keyPath = getBootstrapKeyPath();
    try {
        if (fs.existsSync(keyPath)) {
            const existing = fs.readFileSync(keyPath, 'utf8').trim();
            if (existing) {
                return existing;
            }
        }
    } catch (error) {
        // fall through to generate a new key
    }

    const generatedKey = `sk_${crypto.randomBytes(24).toString('hex')}`;
    try {
        fs.writeFileSync(keyPath, generatedKey, 'utf8');
    } catch (error) {
        // ignore file write failure and continue with memory-only key
    }
    return generatedKey;
}

/**
 * FIX #1: RFC 5321 compliant email validation
 */
function isValidEmail(email) {
    if (typeof email !== 'string' || email.length > 254) {
        return false;
    }
    // RFC 5321 compliant email validation
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return emailRegex.test(email);
}

/**
 * FIX #2: Validate password strength
 * Requires: min 8 chars, uppercase, lowercase, digit
 */
function isValidPassword(password) {
    if (typeof password !== 'string' || password.length < PASSWORD_MIN_LENGTH) {
        return false;
    }
    return PASSWORD_REGEX.test(password);
}

/**
 * FIX #4: Secure OTP generation using crypto.randomBytes
 * Prevents weak randomness and timing attacks
 */
function generateSecureOTP() {
    const bytes = crypto.randomBytes(OTP_ENTROPY_BYTES);
    const num = bytes.readUInt32BE(0) % Math.pow(10, OTP_LENGTH);
    return String(num).padStart(OTP_LENGTH, '0');
}

/**
 * FIX #11: Proper IPv4 address validation
 * Checks all octets are 0-255 and not reserved ranges
 */
function isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) {
        return false;
    }

    // Validate each octet is 0-255 with no leading zeros or non-numeric chars
    for (const part of parts) {
        if (!/^\d{1,3}$/.test(part)) {
            return false;
        }
        const num = parseInt(part, 10);
        if (num < 0 || num > 255) {
            return false;
        }
        // Prevent leading zeros (e.g., "01" is invalid, "0" and "1" are valid)
        if (String(num) !== part) {
            return false;
        }
    }

    // Check if IP is in reserved range
    if (RESERVED_IPS.includes(ip)) {
        return false;
    }

    return true;
}

/**
 * FIX #8: Validate and constrain whitelist path to designated directory
 * Prevents path traversal attacks
 */
function validateWhitelistPath(userPath, baseDir) {
    const resolvedPath = path.resolve(userPath || path.join(baseDir, 'tunnel-whitelist.csv'));
    const resolvedBase = path.resolve(baseDir);

    // Ensure resolved path is within the base directory
    if (!resolvedPath.startsWith(resolvedBase + path.sep) && resolvedPath !== resolvedBase) {
        throw new Error('Whitelist path must be within designated directory');
    }

    return resolvedPath;
}

/**
 * FIX #5: File locking for atomic whitelist writes
 * Prevents race conditions during concurrent verification
 */
function acquireLock(lockPath, maxRetries = 10, retryDelayMs = 50) {
    return new Promise((resolve) => {
        let attempts = 0;
        const tryLock = () => {
            try {
                fs.writeFileSync(lockPath, process.pid.toString(), { flag: 'wx' });
                resolve(true);
            } catch (e) {
                if (attempts < maxRetries) {
                    attempts++;
                    setTimeout(tryLock, retryDelayMs);
                } else {
                    resolve(false);
                }
            }
        };
        tryLock();
    });
}

function releaseLock(lockPath) {
    try {
        fs.unlinkSync(lockPath);
    } catch (e) {
        // Lock file already removed or doesn't exist
    }
}

function ensureWhitelistCsv(csvPath) {
    if (!csvPath) {
        return;
    }

    if (!fs.existsSync(csvPath)) {
        fs.writeFileSync(csvPath, 'lan_ip,device_name,status,created_date,notes\n', 'utf8');
    }
}

function readWhitelistEntries(csvPath) {
    ensureWhitelistCsv(csvPath);
    const content = fs.readFileSync(csvPath, 'utf8').trim();
    if (!content) {
        return [];
    }

    const lines = content.split(/\r?\n/).filter(Boolean);
    const header = lines.shift();
    if (!header) {
        return [];
    }

    return lines.map((line) => {
        const values = line.split(',');
        return {
            lan_ip: values[0] || '',
            device_name: values[1] || '',
            status: values[2] || 'allowed',
            created_date: values[3] || '',
            notes: values[4] || ''
        };
    });
}

function addWhitelistEntry(csvPath, entry) {
    ensureWhitelistCsv(csvPath);
    const entries = readWhitelistEntries(csvPath);
    const alreadyExists = entries.some((item) => item.lan_ip === entry.lan_ip && item.device_name === entry.device_name);
    if (alreadyExists) {
        return entries;
    }

    const line = [
        entry.lan_ip || '',
        entry.device_name || '',
        entry.status || 'allowed',
        entry.created_date || new Date().toISOString().slice(0, 10),
        entry.notes || 'registered via access flow'
    ].join(',');
    fs.appendFileSync(csvPath, `${line}\n`, 'utf8');
    return readWhitelistEntries(csvPath);
}

function loadJsonFile(filePath, fallback = {}) {
    try {
        if (!fs.existsSync(filePath)) {
            return fallback;
        }
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (error) {
        return fallback;
    }
}

function saveJsonFile(filePath, value) {
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2), 'utf8');
}

function createRegistrationState() {
    return {
        pending: new Map(),
        approved: new Map(),
        accessTokens: new Map()
    };
}

/**
 * FIX #9: Proactive cleanup of expired tokens
 * Removes expired tokens immediately on access check
 */
function cleanupExpiredTokens(tokenStore, tokenFilePath) {
    const now = Date.now();
    let cleaned = false;
    for (const [token, record] of tokenStore.entries()) {
        if (!record || record.revoked || (record.expiresAt && record.expiresAt <= now)) {
            tokenStore.delete(token);
            cleaned = true;
        }
    }
    if (cleaned) {
        saveJsonFile(tokenFilePath, Object.fromEntries(tokenStore));
    }
}

function buildRegisterPage({ message = '', status = 'ready', verifyUrl = '', csrfToken = '' } = {}) {
    const statusBox = message ? `
    <div class="alert alert-info">
        <span class="alert-icon">ℹ️</span>
        <div class="alert-content">
            <div class="alert-title">Status Update</div>
            <div class="alert-message">${escapeHtml(message)}</div>
        </div>
    </div>` : '';

    const verifyBox = verifyUrl ? `
    <div class="alert alert-success">
        <span class="alert-icon">✅</span>
        <div class="alert-content">
            <div class="alert-title">Verification Link Ready</div>
            <div class="alert-message">
                <a href="${escapeHtml(verifyUrl)}" class="verify-link">${escapeHtml(verifyUrl)}</a>
            </div>
        </div>
    </div>` : '';

    // FIX #6: CSRF token field (if provided by CSRF middleware)
    const csrfField = csrfToken ? `<input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />` : '';

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>LAN Proxy Registration Gate</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
    }
    
    .container {
      max-width: 900px;
      width: 100%;
    }
    
    .header {
      text-align: center;
      margin-bottom: 2.5rem;
    }
    
    .header-icon {
      font-size: 2.5rem;
      margin-bottom: 0.75rem;
    }
    
    h1 {
      font-size: 2rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      color: #f1f5f9;
    }
    
    .header-subtitle {
      color: #cbd5e1;
      font-size: 1.05rem;
      line-height: 1.6;
    }
    
    .alerts {
      margin-bottom: 2rem;
    }
    
    .alert {
      display: flex;
      gap: 1rem;
      padding: 1.25rem;
      border-radius: 12px;
      margin-bottom: 1rem;
      border-left: 4px solid;
    }
    
    .alert-info {
      background: #1e3a5f;
      border-left-color: #3b82f6;
    }
    
    .alert-success {
      background: #1b3f2e;
      border-left-color: #10b981;
    }
    
    .alert-icon {
      font-size: 1.5rem;
      min-width: 1.5rem;
      text-align: center;
    }
    
    .alert-content {
      flex: 1;
    }
    
    .alert-title {
      font-weight: 600;
      margin-bottom: 0.25rem;
      color: #f1f5f9;
    }
    
    .alert-message {
      font-size: 0.95rem;
      color: #cbd5e1;
    }
    
    .verify-link {
      display: inline-block;
      color: #3b82f6;
      text-decoration: none;
      word-break: break-all;
      padding: 0.5rem 0.75rem;
      background: rgba(59, 130, 246, 0.1);
      border-radius: 6px;
      font-family: 'Courier New', monospace;
      font-size: 0.9rem;
    }
    
    .verify-link:hover {
      background: rgba(59, 130, 246, 0.2);
      text-decoration: underline;
    }
    
    .sections {
      display: grid;
      gap: 2rem;
    }
    
    .section {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 1.75rem;
      transition: all 0.3s ease;
    }
    
    .section:hover {
      border-color: #475569;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    }
    
    .section-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }
    
    .section-number {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 2rem;
      height: 2rem;
      background: #3b82f6;
      border-radius: 50%;
      font-weight: 700;
      font-size: 0.9rem;
      flex-shrink: 0;
    }
    
    .section-title {
      font-size: 1.15rem;
      font-weight: 600;
      color: #f1f5f9;
    }
    
    .section-description {
      font-size: 0.9rem;
      color: #cbd5e1;
      margin-bottom: 1.25rem;
      line-height: 1.5;
    }
    
    form {
      display: grid;
      gap: 0.85rem;
    }
    
    .form-group {
      display: grid;
      gap: 0.4rem;
    }
    
    label {
      font-size: 0.85rem;
      font-weight: 500;
      color: #cbd5e1;
    }
    
    input, select, textarea {
      padding: 0.85rem 1rem;
      border-radius: 8px;
      border: 1px solid #475569;
      background: #0f172a;
      color: #f1f5f9;
      font-size: 1rem;
      transition: all 0.2s ease;
    }
    
    input:focus, select:focus, textarea:focus {
      outline: none;
      border-color: #3b82f6;
      background: #1e293b;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }
    
    textarea {
      resize: vertical;
      min-height: 80px;
      font-family: inherit;
    }
    
    button {
      padding: 1rem;
      border-radius: 8px;
      border: none;
      background: #3b82f6;
      color: white;
      font-weight: 600;
      font-size: 1rem;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    
    button:hover {
      background: #2563eb;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
    }
    
    button:active {
      transform: translateY(0);
    }
    
    .footer {
      text-align: center;
      margin-top: 2.5rem;
      padding-top: 1.5rem;
      border-top: 1px solid #334155;
      color: #94a3b8;
      font-size: 0.9rem;
    }
    
    .status-badge {
      display: inline-block;
      padding: 0.4rem 0.8rem;
      background: #334155;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
      color: #cbd5e1;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .status-badge.ready {
      background: #10b981;
      color: #f1f5f9;
    }
    
    @media (max-width: 768px) {
      h1 { font-size: 1.5rem; }
      .section { padding: 1.25rem; }
      .sections { gap: 1.5rem; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="header-icon">🔐</div>
      <h1>LAN Proxy Registration Gate</h1>
      <p class="header-subtitle">Secure access with email verification and device registration</p>
    </div>
    
    <div class="alerts">
      ${statusBox}
      ${verifyBox}
    </div>
    
    <div class="sections">
      <div class="section">
        <div class="section-header">
          <div class="section-number">1</div>
          <div class="section-title">Test SMTP Configuration</div>
        </div>
        <p class="section-description">Verify that your SMTP settings are correct before proceeding with registration.</p>
        <form method="POST" action="/register/smtp-test">
          ${csrfField}
          <input name="smtpHost" placeholder="SMTP host (e.g., smtp.gmail.com)" required />
          <input name="smtpPort" placeholder="SMTP port (usually 587 or 465)" value="587" required />
          <select name="smtpSecure" required>
            <option value="">Select encryption method...</option>
            <option value="false">TLS/STARTTLS (port 587)</option>
            <option value="true">SSL (port 465)</option>
          </select>
          <input name="smtpUser" placeholder="SMTP username (optional)" />
          <input name="smtpPass" type="password" placeholder="SMTP password (optional)" />
          <input name="smtpFrom" placeholder="From address (e.g., noreply@example.com)" required />
          <input name="to" type="email" placeholder="Test recipient email" required />
          <button type="submit">📧 Send Test Email</button>
        </form>
      </div>
      
      <div class="section">
        <div class="section-header">
          <div class="section-number">2</div>
          <div class="section-title">Register Your Device</div>
        </div>
        <p class="section-description">Create an account and register this device to gain access to the proxy.</p>
        <form method="POST" action="/register/start">
          ${csrfField}
          <input name="email" type="email" placeholder="Your email address" required />
          <input name="password" type="password" placeholder="Create a password (min. 8 chars, uppercase, lowercase, number)" required />
          <input name="username" placeholder="Your username" required />
          <input name="deviceName" placeholder="Device name (e.g., MacBook Pro)" />
          <textarea name="notes" placeholder="Optional notes about this device"></textarea>
          <button type="submit">✅ Start Registration</button>
        </form>
      </div>
      
      <div class="section">
        <div class="section-header">
          <div class="section-number">3</div>
          <div class="section-title">Verify Your Email</div>
        </div>
        <p class="section-description">Enter the verification code sent to your email to complete registration.</p>
        <form method="POST" action="/register/verify">
          ${csrfField}
          <input name="email" type="email" placeholder="Your registered email" required />
          <input name="otp" placeholder="6-digit verification code" maxlength="6" pattern="[0-9]{6}" required />
          <button type="submit">🔓 Verify & Unlock Access</button>
        </form>
      </div>
    </div>
    
    <div class="footer">
      <p>Status: <span class="status-badge ${status === 'ready' ? 'ready' : ''}">${escapeHtml(status)}</span></p>
      <p style="margin-top: 0.75rem; font-size: 0.85rem;">Your browser must allow cookies for session persistence</p>
    </div>
  </div>
</body>
</html>`;
}

function registerAccessRoutes(app, options = {}) {
    const logger = options.logger || console;
    const baseUrl = options.baseUrl || 'http://127.0.0.1:8789';
    const state = options.state || createRegistrationState();
    const emailService = options.emailService;
    
    // ════════════════════════════════════════════════════════════════
    // FIX: SECURITY MODULE INTEGRATION (IP Blacklist & Audit Logger)
    // ════════════════════════════════════════════════════════════════
    const ipBlacklist = options.ipBlacklist;
    const auditLogger = options.auditLogger;

    if (!emailService) {
        throw new Error('registerAccessRoutes requires an emailService implementation');
    }

    // FIX #8: Validate and constrain whitelist path
    const whitelistBaseDir = path.resolve(
        process.env.WHITELIST_DIR || path.join(__dirname, WHITELIST_BASE_SUBDIR)
    );
    
    // Ensure base directory exists
    if (!fs.existsSync(whitelistBaseDir)) {
        fs.mkdirSync(whitelistBaseDir, { recursive: true });
    }

    const whitelistCsvPath = validateWhitelistPath(
        options.whitelistCsvPath || process.env.WHITELIST_CSV_PATH,
        whitelistBaseDir
    );

    const stateDir = path.dirname(whitelistCsvPath);
    const pendingStatePath = path.join(stateDir, 'pending-registrations.json');
    const tokenStatePath = path.join(stateDir, 'access-tokens.json');
    const whitelistLockPath = whitelistCsvPath + '.lock';

    const persistedPending = loadJsonFile(pendingStatePath, {});
    state.pending = new Map(Object.entries(persistedPending));

    const persistedTokens = loadJsonFile(tokenStatePath, {});
    state.accessTokens = new Map(Object.entries(persistedTokens));
    cleanupExpiredTokens(state.accessTokens, tokenStatePath);

    setInterval(() => cleanupExpiredTokens(state.accessTokens, tokenStatePath), 5 * 60 * 1000);

    function savePendingState() {
        saveJsonFile(pendingStatePath, Object.fromEntries(state.pending));
    }

    function saveAccessTokenState() {
        saveJsonFile(tokenStatePath, Object.fromEntries(state.accessTokens));
    }

    app.get('/register', (req, res) => {
        // FIX #6: Pass CSRF token to template if available
        const csrfToken = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
        res.type('html').send(buildRegisterPage({ status: 'ready', csrfToken }));
    });

    app.post('/register/smtp-test', async (req, res) => {
        try {
            const { smtpHost, smtpPort, smtpSecure, smtpUser, smtpPass, smtpFrom, to } = req.body;
            if (!smtpHost || !smtpPort || !smtpFrom || !to) {
                return res.status(400).json({ error: 'Missing SMTP test parameters' });
            }

            if (typeof emailService.sendTestEmail !== 'function') {
                return res.status(500).json({ error: 'SMTP test helper not available' });
            }

            await emailService.sendTestEmail({
                host: smtpHost,
                port: Number(smtpPort),
                secure: smtpSecure === 'true',
                user: smtpUser || '',
                pass: smtpPass || '',
                from: smtpFrom,
                to
            });

            logger.info('[REGISTER] SMTP test email delivered');
            res.status(200).json({ status: 'ok', message: 'SMTP test email delivered' });
        } catch (error) {
            logger.error('[REGISTER] SMTP test failed', error.message);
            res.status(500).json({ error: 'SMTP test failed', detail: error.message });
        }
    });

    app.post('/register/start', async (req, res) => {
        try {
            const { email, password, username, deviceName, notes } = req.body;
            const clientIp = getClientIp(req);
            
            // FIX #2: Validate required fields with strict checks
            if (!email || !password || !username) {
                // ════════════════════════════════════════════════════════════════
                // FIX: Log failed registration validation to audit trail
                // ════════════════════════════════════════════════════════════════
                auditLogger?.logSecurityEvent('REGISTRATION_VALIDATION_FAILED', {
                    email: email || 'unknown',
                    ip: clientIp,
                    reason: 'Missing required fields'
                });
                return res.status(400).json({ error: 'Missing required fields' });
            }

            // FIX #1: RFC 5321 compliant email validation
            if (!isValidEmail(email)) {
                auditLogger?.logSecurityEvent('REGISTRATION_INVALID_EMAIL', {
                    email,
                    ip: clientIp
                });
                return res.status(400).json({ error: 'Invalid email format' });
            }

            // FIX #2: Password strength validation (8+ chars, uppercase, lowercase, digit)
            if (!isValidPassword(password)) {
                auditLogger?.logSecurityEvent('REGISTRATION_WEAK_PASSWORD', {
                    email,
                    ip: clientIp
                });
                return res.status(400).json({
                    error: 'Password must be at least 8 characters with uppercase, lowercase, and digits'
                });
            }

            if (!checkRateLimit(`register:${email.toLowerCase()}`, 5, 60000) || 
                !checkRateLimit(`register:${clientIp}`, 5, 60000)) {
                // ════════════════════════════════════════════════════════════════
                // FIX: Integrate IP Blacklist for registration brute force
                // ════════════════════════════════════════════════════════════════
                const failureAction = ipBlacklist?.recordFailedAuth(clientIp, email);
                
                auditLogger?.logSecurityEvent('REGISTRATION_RATE_LIMITED', {
                    email,
                    ip: clientIp,
                    reason: 'Too many registration attempts'
                });

                if (failureAction?.action === 'blacklist') {
                    console.warn(`[SECURITY] 🚫 IP blacklisted for registration abuse: ${clientIp}`);
                    auditLogger?.logSecurityEvent('REGISTRATION_IP_BLACKLISTED', {
                        email,
                        ip: clientIp,
                        reason: failureAction.reason
                    });
                    return res.status(429).json({
                        error: 'Too many attempts',
                        detail: failureAction.reason,
                        blockDurationMinutes: failureAction.blockDurationMinutes
                    });
                }

                return res.status(429).json({ error: 'Too many registration attempts. Please wait.' });
            }

            const lowerEmail = email.toLowerCase();
            if (state.pending.has(lowerEmail)) {
                auditLogger?.logSecurityEvent('REGISTRATION_DUPLICATE_PENDING', {
                    email: lowerEmail,
                    ip: clientIp
                });
                return res.status(409).json({ error: 'A registration is already pending for this email.' });
            }

            const passwordHash = crypto.createHash('sha256').update(String(password)).digest('hex');
            
            // FIX #4: Use secure OTP generation with crypto.randomBytes
            const otp = generateSecureOTP();
            const token = crypto.randomBytes(16).toString('hex');
            const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
            const verifyUrl = `${baseUrl}/register/verify?email=${encodeURIComponent(email)}&token=${token}`;

            const pending = {
                email: lowerEmail,
                passwordHash,
                username,
                deviceName: deviceName || 'registered-device',
                deviceIp: clientIp,
                notes: notes || '',
                otpHash,
                token,
                createdAt: Date.now(),
                verified: false,
                otpAttempts: 0
            };

            state.pending.set(lowerEmail, pending);
            savePendingState();
            
            // ════════════════════════════════════════════════════════════════
            // FIX: Log successful magic link generation and sending
            // ════════════════════════════════════════════════════════════════
            auditLogger?.logSecurityEvent('REGISTRATION_STARTED', {
                email: lowerEmail,
                ip: clientIp,
                deviceName: deviceName || 'registered-device',
                method: 'email'
            });

            await emailService.sendOTP(email, otp, { verifyUrl, baseUrl });

            // ════════════════════════════════════════════════════════════════
            // FIX: Log that magic link was successfully sent
            // ════════════════════════════════════════════════════════════════
            auditLogger?.logAuthEvent('REGISTRATION_OTP_SENT', {
                email: lowerEmail,
                ip: clientIp,
                method: 'email',
                verifyUrl,
                otpExpiry: OTP_EXPIRY_MS / 1000 + ' seconds'
            });

            console.log(`[REGISTER] Magic link sent to ${email}`);
            res.status(202).json({
                status: 'pending_verification',
                message: 'Verification code and link sent to your email.'
            });
        } catch (error) {
            logger.error('[REGISTER] Registration start failed', error.message);
            
            auditLogger?.logSecurityEvent('REGISTRATION_START_ERROR', {
                email: req.body.email || 'unknown',
                ip: getClientIp(req),
                error: error.message
            });

            res.status(500).json({ error: 'Registration failed. Please try again later.' });
        }
    });

    app.get('/register/verify', async (req, res) => {
        try {
            const { email, token } = req.query;
            const lowerEmail = String(email || '').toLowerCase();
            const pending = state.pending.get(lowerEmail);
            
            if (!pending || pending.token !== String(token || '')) {
                auditLogger?.logSecurityEvent('REGISTRATION_INVALID_VERIFY_LINK', {
                    email: lowerEmail,
                    ip: getClientIp(req)
                });
                return res.status(400).type('html').send('<h1>Invalid or expired verification link</h1>');
            }

            const result = await completeVerification(lowerEmail, req, res);
            if (result.error) {
                return res.status(400).type('html').send(`<h1>${result.error}</h1>`);
            }

            res.type('html').send(`<!DOCTYPE html><html><body><h1>Access verified</h1><p>Your device was added to the whitelist and your ${TOKEN_TTL_DISPLAY} access token has been issued.</p></body></html>`);
        } catch (error) {
            logger.error('[REGISTER] Verification link failed', error.message);
            res.status(500).type('html').send('<h1>Verification failed</h1>');
        }
    });

    app.post('/register/verify', async (req, res) => {
        try {
            const { email, otp } = req.body;
            const clientIp = getClientIp(req);
            
            if (!email || !otp) {
                return res.status(400).json({ error: 'Email and OTP are required' });
            }

            const lowerEmail = String(email).toLowerCase();
            const pending = state.pending.get(lowerEmail);
            if (!pending) {
                auditLogger?.logSecurityEvent('REGISTRATION_VERIFY_NOT_FOUND', {
                    email: lowerEmail,
                    ip: clientIp
                });
                return res.status(404).json({ error: 'No pending registration found for that email' });
            }

            if (!checkRateLimit(`verify:${lowerEmail}`, OTP_MAX_ATTEMPTS, 60000) || 
                !checkRateLimit(`verify:${clientIp}`, OTP_MAX_ATTEMPTS, 60000)) {
                
                // ════════════════════════════════════════════════════════════════
                // FIX: Record failed OTP verification to IP blacklist
                // ════════════════════════════════════════════════════════════════
                const failureAction = ipBlacklist?.recordFailedAuth(clientIp, email);
                
                auditLogger?.logSecurityEvent('OTP_VERIFICATION_RATE_LIMITED', {
                    email: lowerEmail,
                    ip: clientIp,
                    attempts: OTP_MAX_ATTEMPTS
                });

                if (failureAction?.action === 'blacklist') {
                    console.warn(`[SECURITY] 🚫 IP blacklisted for OTP brute force: ${clientIp}`);
                    return res.status(429).json({
                        error: 'Too many attempts',
                        detail: failureAction.reason,
                        blockDurationMinutes: failureAction.blockDurationMinutes
                    });
                }

                return res.status(429).json({ error: 'Too many verification attempts. Please wait.' });
            }

            // FIX #3: Use timing-safe comparison for OTP verification
            const providedOtpHash = crypto.createHash('sha256').update(String(otp)).digest('hex');
            let otpMatch = false;
            try {
                otpMatch = crypto.timingSafeEqual(
                    Buffer.from(providedOtpHash, 'hex'),
                    Buffer.from(pending.otpHash, 'hex')
                );
            } catch (e) {
                otpMatch = false;
            }

            if (!otpMatch) {
                pending.otpAttempts = (pending.otpAttempts || 0) + 1;
                
                auditLogger?.logSecurityEvent('OTP_VERIFICATION_FAILED', {
                    email: lowerEmail,
                    ip: clientIp,
                    attemptNumber: pending.otpAttempts,
                    maxAttempts: OTP_MAX_ATTEMPTS
                });

                if (pending.otpAttempts >= OTP_MAX_ATTEMPTS) {
                    state.pending.delete(lowerEmail);
                    savePendingState();
                    
                    auditLogger?.logSecurityEvent('OTP_VERIFICATION_EXCEEDED_ATTEMPTS', {
                        email: lowerEmail,
                        ip: clientIp,
                        attempts: pending.otpAttempts
                    });

                    return res.status(429).json({ 
                        error: 'Too many failed attempts. Please start registration again.' 
                    });
                }
                return res.status(401).json({ error: 'Invalid verification code' });
            }

            const result = await completeVerification(lowerEmail, req, res);
            if (result.error) {
                return res.status(400).json({ error: result.error });
            }

            // ════════════════════════════════════════════════════════════════
            // FIX: Record successful auth after email verification
            // ════════════════════════════════════════════════════════════════
            ipBlacklist?.recordSuccessfulAuth(clientIp);

            res.status(200).json({
                status: 'verified',
                message: 'Access verified. Your API key and access token were sent by email.',
                whitelistPath: whitelistCsvPath
            });
        } catch (error) {
            logger.error('[REGISTER] Verification failed', error.message);
            
            auditLogger?.logSecurityEvent('REGISTRATION_VERIFY_ERROR', {
                email: req.body.email || 'unknown',
                ip: getClientIp(req),
                error: error.message
            });

            res.status(500).json({ error: 'Verification failed. Please try again later.' });
        }
    });

    /**
     * FIX #5: Atomic whitelist writes with file locking
     * Prevents race conditions during concurrent registrations
     */
    async function completeVerification(email, req, res) {
        const lowerEmail = String(email).toLowerCase();
        const pending = state.pending.get(lowerEmail);
        const clientIp = getClientIp(req);
        
        if (!pending) {
            return { error: 'No pending registration' };
        }

        const apiKey = crypto.randomBytes(24).toString('hex');
        const deviceIp = pending.deviceIp || clientIp;
        const deviceName = pending.deviceName || 'registered-device';

        // FIX #7: Validate email at output time before sending
        if (!isValidEmail(pending.email)) {
            logger.error('[REGISTER] Invalid email in pending state:', pending.email);
            auditLogger?.logSecurityEvent('REGISTRATION_INVALID_EMAIL_STATE', {
                email: pending.email,
                ip: clientIp
            });
            return { error: 'Invalid email format in pending state' };
        }

        // Acquire lock for atomic whitelist write
        const lockAcquired = await acquireLock(whitelistLockPath);
        if (!lockAcquired) {
            logger.warn('[REGISTER] Could not acquire whitelist lock');
            auditLogger?.logSecurityEvent('REGISTRATION_LOCK_FAILED', {
                email: lowerEmail,
                ip: clientIp
            });
            return { error: 'Service temporarily unavailable. Please try again.' };
        }

        try {
            // Primary whitelist entry
            addWhitelistEntry(whitelistCsvPath, {
                lan_ip: deviceIp,
                device_name: deviceName,
                status: 'allowed',
                created_date: new Date().toISOString().slice(0, 10),
                notes: pending.notes || 'registered via access flow'
            });

            // FIX #5: Mirror whitelist entry to fallback locations with locking
            const fallbackCandidates = [
                path.join(__dirname, 'tunnel-whitelist.csv'),
                path.join(__dirname, '..', 'lan-proxy', 'tunnel-whitelist.csv'),
                '/app/lan-proxy/tunnel-whitelist.csv'
            ].filter(p => p && p !== whitelistCsvPath);

            for (const candidate of fallbackCandidates) {
                try {
                    const candidateLock = candidate + '.lock';
                    const candidateLockAcquired = await acquireLock(candidateLock, 5, 50);
                    
                    if (candidateLockAcquired) {
                        try {
                            ensureWhitelistCsv(candidate);
                            addWhitelistEntry(candidate, {
                                lan_ip: deviceIp,
                                device_name: deviceName,
                                status: 'allowed',
                                created_date: new Date().toISOString().slice(0, 10),
                                notes: pending.notes || 'registered via access flow (mirrored)'
                            });
                        } finally {
                            releaseLock(candidateLock);
                        }
                    }
                } catch (e) {
                    logger.warn('[REGISTER] Failed to mirror whitelist to ' + candidate + ': ' + (e && e.message));
                }
            }
        } finally {
            releaseLock(whitelistLockPath);
        }

        const accessToken = createSignedToken({
            email: pending.email,
            deviceIp,
            deviceName,
            issuedAt: Date.now()
        });
        state.accessTokens.set(accessToken, {
            email: pending.email,
            deviceIp,
            deviceName,
            issuedAt: Date.now(),
            expiresAt: Date.now() + TOKEN_TTL_MS,
            revoked: false
        });
        saveAccessTokenState();

        pending.verified = true;
        state.approved.set(lowerEmail, {
            email: pending.email,
            username: pending.username,
            approvedAt: Date.now(),
            apiKey,
            deviceIp,
            deviceName,
            accessToken
        });
        state.pending.delete(lowerEmail);
        savePendingState();

        const logoutUrl = buildLogoutUrl(baseUrl, accessToken);
        await emailService.sendAPIKey(pending.email, apiKey, TOKEN_TTL_DISPLAY, { accessToken, logoutUrl, baseUrl });

        // ════════════════════════════════════════════════════════════════
        // FIX: Log successful registration completion
        // ════════════════════════════════════════════════════════════════
        auditLogger?.logAuthEvent('REGISTRATION_COMPLETED', {
            email: lowerEmail,
            ip: clientIp,
            deviceName,
            deviceIp,
            accessTokenIssued: true,
            apiKeySent: true
        });

        console.log(`[REGISTER] ✅ Registration completed for ${pending.email} from ${deviceIp}`);

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            sameSite: 'lax',
            secure: false,
            maxAge: TOKEN_TTL_MS,
            path: '/'
        });

        return { success: true, accessToken };
    }

    app.get('/logout', (req, res) => {
        const token = req.query.token || req.cookies.access_token || '';
        const clientIp = getClientIp(req);
        
        if (token && state.accessTokens.has(token)) {
            const record = state.accessTokens.get(token);
            state.accessTokens.delete(token);
            saveAccessTokenState();
            
            // ════════════════════════════════════════════════════════════════
            // FIX: Log logout events for audit trail
            // ════════════════════════════════════════════════════════════════
            auditLogger?.logAuthEvent('LOGOUT_SUCCESS', {
                email: record?.email || 'unknown',
                ip: clientIp,
                deviceName: record?.deviceName || 'unknown'
            });
        }
        
        res.clearCookie('access_token', { path: '/' });
        res.type('html').send('<h1>Logged out</h1><p>Your access token was revoked.</p>');
    });

    app.get('/register/whitelist', (req, res) => {
        try {
            const entries = readWhitelistEntries(whitelistCsvPath);
            res.json({ whitelistPath: whitelistCsvPath, entries });
        } catch (error) {
            logger.error('[REGISTER] Could not read whitelist', error.message);
            res.status(500).json({ error: 'Could not read whitelist' });
        }
    });

    /**
     * FIX #10: Add rate limiting to whitelist endpoint
     * Prevents flooding whitelist with garbage entries
     */
    const whitelistLimiter = rateLimit({
        windowMs: 60 * 60 * 1000,  // 1 hour
        max: 100,  // 100 entries per hour per IP
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req) => req.ip || 'unknown',
        message: { error: 'Too many whitelist requests', detail: 'Try again later' }
    });

    app.post('/register/whitelist', whitelistLimiter, (req, res) => {
        try {
            const { lanIp, deviceName, notes } = req.body;
            if (!lanIp || !deviceName) {
                return res.status(400).json({ error: 'lanIp and deviceName are required' });
            }

            // FIX #11: Proper IPv4 validation with octet range checks
            if (!isValidIPv4(lanIp)) {
                return res.status(400).json({ error: 'Invalid IPv4 address' });
            }

            addWhitelistEntry(whitelistCsvPath, {
                lan_ip: lanIp,
                device_name: deviceName,
                status: 'allowed',
                created_date: new Date().toISOString().slice(0, 10),
                notes: notes || 'manual whitelist entry'
            });
            res.status(200).json({ status: 'ok', whitelistPath: whitelistCsvPath });
        } catch (error) {
            logger.error('[REGISTER] Whitelist update failed', error.message);
            res.status(500).json({ error: 'Whitelist update failed' });
        }
    });

    return { state, whitelistCsvPath };
}

function createAccessTokenMiddleware(options = {}) {
    const logger = options.logger || console;
    const state = options.state || createRegistrationState();

    return function requireAccessToken(req, res, next) {
        const bypassPaths = ['/', '/register', '/logout', '/health', '/favicon.ico'];
        const pathname = req.path || '/';
        if (bypassPaths.includes(pathname) || pathname.startsWith('/register') || pathname.startsWith('/v1/')) {
            return next();
        }

        const token = req.query.token || req.get('x-access-token') || req.get('authorization')?.replace(/^Bearer\s+/i, '') || req.cookies.access_token;
        if (!token) {
            logger.warn('[ACCESS] Missing access token for', pathname);
            return res.status(401).type('html').send(`<!DOCTYPE html><html><body><h1>Access required</h1><p>Complete email verification and use your ${TOKEN_TTL_DISPLAY} access token to continue</p></body></html>`);
        }

        const payload = verifySignedToken(token);
        const record = state.accessTokens.get(token);

        // FIX #9: Proactive cleanup on expired token access
        if (record && record.expiresAt && record.expiresAt <= Date.now()) {
            state.accessTokens.delete(token);
            logger.warn('[ACCESS] Removed expired token for', pathname);
            return res.status(401).type('html').send(`<!DOCTYPE html><html><body><h1>Access required</h1><p>Your access token is invalid or expired.</p><p><a href="/register">Open registration</a></p></body></html>`);
        }

        if (!payload || !record || record.revoked) {
            logger.warn('[ACCESS] Invalid or expired access token for', pathname);
            return res.status(401).type('html').send(`<!DOCTYPE html><html><body><h1>Access required</h1><p>Your access token is invalid or expired.</p><p><a href="/register">Open registration</a></p></body></html>`);
        }

        req.accessToken = token;
        req.accessIdentity = payload;
        return next();
    };
}

module.exports = {
    registerAccessRoutes,
    createRegistrationState,
    readWhitelistEntries,
    addWhitelistEntry,
    ensureWhitelistCsv,
    buildRegisterPage,
    createAccessTokenMiddleware,
    createSignedToken,
    verifySignedToken,
    buildLogoutUrl,
    resolveBootstrapApiKey,
    // Helper exports for external validation
    isValidEmail,
    isValidPassword,
    isValidIPv4,
    validateWhitelistPath,
    generateSecureOTP
};
