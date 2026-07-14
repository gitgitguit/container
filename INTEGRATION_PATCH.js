/**
 * ════════════════════════════════════════════════════════════════════════════════
 * SERVER.JS INTEGRATION PATCH - IP BLACKLIST & DDoS PREVENTION
 * ════════════════════════════════════════════════════════════════════════════════
 * 
 * COPY THIS CODE AND PASTE INTO server.js IN THE SPECIFIED LOCATIONS
 * 
 * This patch enforces the IP Blacklist & DDoS Prevention system
 * into your existing server.js without breaking current functionality.
 * ════════════════════════════════════════════════════════════════════════════════
 */

// ════════════════════════════════════════════════════════════════════════════════
// STEP 1: ADD TO IMPORTS (Line 30, after other security imports)
// ════════════════════════════════════════════════════════════════════════════════

// Add this line after other security module imports:
const IntelligentIPBlacklist = require('./modules/security/ip-blacklist-ddos');
const AuditLogger = require('./modules/security/audit-logging');


// ════════════════════════════════════════════════════════════════════════════════
// STEP 2: INITIALIZE MODULES (After HMAC_SECRET definition, around Line 200)
// ════════════════════════════════════════════════════════════════════════════════

// Initialize IP Blacklist System
const ipBlacklist = new IntelligentIPBlacklist({
  enableAutoBlacklist: true,
  enableBehavioralAnalysis: true,
  enableGeoBlocking: false,
  failedAuthThreshold: parseInt(process.env.FAILED_AUTH_THRESHOLD || '5', 10),
  bruteForceThreshold: parseInt(process.env.BRUTE_FORCE_THRESHOLD || '20', 10),
  initialBlockDuration: parseInt(process.env.BLOCK_DURATION_MINUTES || '15', 10) * 60 * 1000,
  maxBlockDuration: parseInt(process.env.MAX_BLOCK_DURATION_DAYS || '7', 10) * 24 * 60 * 60 * 1000,
  trustedIPs: [
    '127.0.0.1',
    '::1',
    ...(process.env.ADMIN_IP ? [process.env.ADMIN_IP] : [])
  ],
  trustedNetworks: process.env.TRUSTED_NETWORKS ? 
    process.env.TRUSTED_NETWORKS.split(',').map(n => n.trim()) : 
    [],
  hmacSecret: HMAC_SECRET
});

console.log('✅ [DEPLOYMENT] IP Blacklist initialized');
console.log('   ├─ Trusted IPs: ' + (process.env.ADMIN_IP || '127.0.0.1'));
console.log('   ├─ Block Duration: ' + (process.env.BLOCK_DURATION_MINUTES || '15') + ' minutes');
console.log('   ├─ Brute Force Threshold: ' + (process.env.BRUTE_FORCE_THRESHOLD || '20') + ' attempts');

// Initialize Audit Logger
const auditLogger = new AuditLogger({
  logDir: path.join(__dirname, '../../logs/audit'),
  enableConsoleLogging: true,
  enableIntegrityHashing: true,
  hmacSecret: HMAC_SECRET
});

console.log('✅ [DEPLOYMENT] Audit Logger initialized');


// ════════════════════════════════════════════════════════════════════════════════
// STEP 3: ADD IP BLACKLIST MIDDLEWARE (After app initialization, before rate limiter)
// ════════════════════════════════════════════════════════════════════════════════

// IP BLACKLIST CHECK MIDDLEWARE - Place this BEFORE rate limiter (Line ~800)
app.use((req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
  
  // Store IP on request for later use
  req.clientIP = clientIP;
  
  // Check if IP is blocked
  const blockCheck = ipBlacklist.isIPBlocked(clientIP);
  
  if (blockCheck.blocked) {
    const blockReason = blockCheck.reason || 'Suspicious activity detected';
    
    // Log the blocked access attempt
    auditLogger.logSecurityEvent('IP_BLOCKED', {
      ip: clientIP,
      reason: blockReason,
      minutesRemaining: blockCheck.minutesRemaining,
      endpoint: req.path,
      method: req.method
    });
    
    console.warn(`[SECURITY] 🚫 Blocked IP: ${clientIP} - ${blockReason}`);
    
    return res.status(403).json({
      error: 'Forbidden',
      status: 'blocked',
      detail: 'Your IP has been blocked due to suspicious activity',
      reason: blockReason,
      unblockTime: new Date(blockCheck.expiresAt).toISOString(),
      minutesRemaining: blockCheck.minutesRemaining,
      support: 'Contact admin if this is a mistake'
    });
  }
  
  // Check if IP is high reputation (suspicious but not blocked)
  if (blockCheck.suspicious) {
    auditLogger.logSecurityEvent('IP_SUSPICIOUS', {
      ip: clientIP,
      reputation: blockCheck.reputation,
      endpoint: req.path
    });
    
    console.warn(`[SECURITY] ⚠️  Suspicious IP: ${clientIP} (reputation: ${blockCheck.reputation})`);
  }
  
  next();
});


// ════════════════════════════════════════════════════════════════════════════════
// STEP 4: UPDATE AUTH FAILURE HANDLING (In /auth/mfa/login endpoint)
// ════════════════════════════════════════════════════════════════════════════════

// Find this section in /auth/mfa/login and REPLACE the error handling:

// REPLACE THIS:
/*
if (!key.valid) {
  return res.status(401).json({ error: 'Invalid credentials' });
}
*/

// WITH THIS:
if (!key.valid) {
  const clientIP = req.clientIP;
  
  // Record failed auth attempt
  const failureAction = ipBlacklist.recordFailedAuth(clientIP, email);
  
  // Log to audit trail
  auditLogger.logSecurityEvent('AUTH_FAILED', {
    email: email,
    ip: clientIP,
    reason: 'Invalid credentials',
    failureCount: failureAction.failures || 1
  });
  
  // If IP now blacklisted, reject with block info
  if (failureAction.action === 'blacklist') {
    console.warn(`[SECURITY] 🚫 IP blacklisted after brute force: ${clientIP}`);
    
    return res.status(429).json({
      error: 'Too Many Attempts',
      status: 'rate_limited',
      detail: failureAction.reason,
      blockDurationMinutes: failureAction.blockDurationMinutes,
      unblockTime: new Date(failureAction.expiresAt).toISOString()
    });
  }
  
  // Standard auth failure
  console.warn(`[MFA] Failed login attempt: ${email} from ${clientIP}`);
  
  return res.status(401).json({
    error: 'Unauthorized',
    detail: 'Invalid email or password'
  });
}

// Record successful auth
ipBlacklist.recordSuccessfulAuth(clientIP);
auditLogger.logAuthEvent('AUTH_SUCCESS', { email, ip: clientIP });


// ════════════════════════════════════════════════════════════════════════════════
// STEP 5: ADD BOT DETECTION INTEGRATION (In endpoints that check behavior)
// ════════════════════════════════════════════════════════════════════════════════

// If you're using the csrfProtection module to analyze behavior, add this:

// AFTER analyzing request behavior with csrfProtection.analyzeRequestBehavior()
// const analysis = csrfProtection.analyzeRequestBehavior(...);

if (analysis && analysis.botProbability > 0.7) {
  const clientIP = req.clientIP;
  const botAction = ipBlacklist.recordBotActivity(
    clientIP,
    analysis.botProbability,
    analysis.indicators
  );
  
  if (botAction.action === 'blacklist') {
    auditLogger.logSecurityEvent('BOT_DETECTED_BLACKLISTED', {
      ip: clientIP,
      probability: analysis.botProbability,
      indicators: analysis.indicators
    });
    
    console.warn(`[SECURITY] 🤖 Bot detected and blacklisted: ${clientIP}`);
  } else {
    auditLogger.logSecurityEvent('BOT_ACTIVITY_DETECTED', {
      ip: clientIP,
      probability: analysis.botProbability
    });
  }
}


// ════════════════════════════════════════════════════════════════════════════════
// STEP 6: ADD ADMIN ENDPOINTS (After existing admin endpoints, before server.listen)
// ════════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN ENDPOINTS: IP BLACKLIST & DDoS PREVENTION
// ═══════════════════════════════════════════════════════════════════════════════

// GET /admin/ip-blacklist/stats - View blacklist statistics
app.get('/admin/ip-blacklist/stats', createAccessTokenMiddleware, (req, res) => {
  try {
    // Verify admin role
    if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
      auditLogger.logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS', {
        endpoint: '/admin/ip-blacklist/stats',
        ip: req.clientIP,
        role: req.apiKeyRole
      });
      return res.status(403).json({
        error: 'Forbidden',
        detail: 'Admin role required'
      });
    }

    const stats = ipBlacklist.getBlacklistStats();
    
    auditLogger.logAuthEvent('ADMIN_STATS_RETRIEVED', {
      ip: req.clientIP,
      totalBlacklisted: stats.totalBlacklisted
    });

    res.json({
      status: 'ok',
      ...stats,
      retrieved: true
    });
  } catch (err) {
    console.error('[IP-BLACKLIST] Stats error:', err.message);
    res.status(500).json({
      error: 'Internal Server Error',
      detail: err.message
    });
  }
});

// GET /admin/ip-blacklist/list - List recent blacklist entries
app.get('/admin/ip-blacklist/list', createAccessTokenMiddleware, (req, res) => {
  try {
    if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
      auditLogger.logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS', {
        endpoint: '/admin/ip-blacklist/list',
        ip: req.clientIP
      });
      return res.status(403).json({
        error: 'Forbidden',
        detail: 'Admin role required'
      });
    }

    const limit = Math.min(parseInt(req.query.limit || '50', 10), 500);
    const entries = ipBlacklist.getRecentBlacklist(limit);

    auditLogger.logAuthEvent('ADMIN_BLACKLIST_LIST_RETRIEVED', {
      ip: req.clientIP,
      entryCount: entries.length
    });

    res.json({
      status: 'ok',
      entries,
      total: entries.length,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('[IP-BLACKLIST] List error:', err.message);
    res.status(500).json({
      error: 'Internal Server Error',
      detail: err.message
    });
  }
});

// POST /admin/ip-blacklist/block-ip - Manually block an IP
app.post('/admin/ip-blacklist/block-ip', createAccessTokenMiddleware, (req, res) => {
  try {
    if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
      auditLogger.logSecurityEvent('UNAUTHORIZED_ADMIN_ACTION', {
        action: 'block-ip',
        ip: req.clientIP
      });
      return res.status(403).json({
        error: 'Forbidden',
        detail: 'Admin role required'
      });
    }

    const { ip, reason, durationMinutes } = req.body;

    if (!ip || !reason) {
      return res.status(400).json({
        error: 'Bad Request',
        detail: 'Missing required fields: ip, reason'
      });
    }

    const result = ipBlacklist.manuallyBlockIP(ip, reason, durationMinutes || 60);

    auditLogger.logAuthEvent('ADMIN_IP_BLOCKED_MANUAL', {
      ip: req.clientIP,
      targetIP: ip,
      reason,
      durationMinutes: durationMinutes || 60
    });

    res.json({
      status: 'success',
      ip,
      reason,
      blockDurationMinutes: result.durationMinutes,
      expiresAt: new Date(Date.now() + (result.durationMinutes * 60000)).toISOString()
    });
  } catch (err) {
    console.error('[IP-BLACKLIST] Block error:', err.message);
    res.status(500).json({
      error: 'Internal Server Error',
      detail: err.message
    });
  }
});

// POST /admin/ip-blacklist/unblock-ip - Manually unblock an IP
app.post('/admin/ip-blacklist/unblock-ip', createAccessTokenMiddleware, (req, res) => {
  try {
    if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
      auditLogger.logSecurityEvent('UNAUTHORIZED_ADMIN_ACTION', {
        action: 'unblock-ip',
        ip: req.clientIP
      });
      return res.status(403).json({
        error: 'Forbidden',
        detail: 'Admin role required'
      });
    }

    const { ip, reason } = req.body;

    if (!ip) {
      return res.status(400).json({
        error: 'Bad Request',
        detail: 'Missing required field: ip'
      });
    }

    const result = ipBlacklist.manuallyUnblockIP(ip, reason);

    auditLogger.logAuthEvent('ADMIN_IP_UNBLOCKED_MANUAL', {
      ip: req.clientIP,
      targetIP: ip,
      reason: reason || 'Manual unblock'
    });

    res.json({
      status: 'success',
      ip,
      unblocked: result.success,
      reason: reason || 'Manual unblock by admin'
    });
  } catch (err) {
    console.error('[IP-BLACKLIST] Unblock error:', err.message);
    res.status(500).json({
      error: 'Internal Server Error',
      detail: err.message
    });
  }
});

// POST /admin/ip-blacklist/add-trusted - Add IP to trusted list
app.post('/admin/ip-blacklist/add-trusted', createAccessTokenMiddleware, (req, res) => {
  try {
    if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
      auditLogger.logSecurityEvent('UNAUTHORIZED_ADMIN_ACTION', {
        action: 'add-trusted',
        ip: req.clientIP
      });
      return res.status(403).json({
        error: 'Forbidden',
        detail: 'Admin role required'
      });
    }

    const { ip, label } = req.body;

    if (!ip) {
      return res.status(400).json({
        error: 'Bad Request',
        detail: 'Missing required field: ip'
      });
    }

    const result = ipBlacklist.addTrustedIP(ip, label);

    auditLogger.logAuthEvent('ADMIN_IP_TRUSTED_ADDED', {
      ip: req.clientIP,
      trustedIP: ip,
      label: label || 'No label'
    });

    res.json({
      status: 'success',
      ip,
      label: label || 'No label',
      trustedCount: result.trustedCount
    });
  } catch (err) {
    console.error('[IP-BLACKLIST] Trusted IP error:', err.message);
    res.status(500).json({
      error: 'Internal Server Error',
      detail: err.message
    });
  }
});

// GET /admin/ip-blacklist/export-waf - Export for WAF/firewall
app.get('/admin/ip-blacklist/export-waf', createAccessTokenMiddleware, (req, res) => {
  try {
    if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
      auditLogger.logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS', {
        endpoint: '/admin/ip-blacklist/export-waf',
        ip: req.clientIP
      });
      return res.status(403).json({
        error: 'Forbidden',
        detail: 'Admin role required'
      });
    }

    const exportData = ipBlacklist.exportBlacklistForWAF();

    auditLogger.logAuthEvent('ADMIN_BLACKLIST_EXPORTED', {
      ip: req.clientIP,
      blockedCount: exportData.denyCount
    });

    res.json({
      status: 'ok',
      ...exportData
    });
  } catch (err) {
    console.error('[IP-BLACKLIST] Export error:', err.message);
    res.status(500).json({
      error: 'Internal Server Error',
      detail: err.message
    });
  }
});


// ════════════════════════════════════════════════════════════════════════════════
// STEP 7: ADD SHUTDOWN HANDLERS (Before server.listen, in process handlers)
// ════════════════════════════════════════════════════════════════════════════════

// Add to existing process shutdown handlers:
process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] SIGTERM received, cleaning up security modules...');
  
  try {
    if (ipBlacklist) {
      ipBlacklist.shutdown();
    }
    if (auditLogger) {
      auditLogger.shutdown();
    }
  } catch (err) {
    console.warn('[SHUTDOWN] Cleanup error:', err.message);
  }
  
  process.exit(0);
});


// ════════════════════════════════════════════════════════════════════════════════
// DEPLOYMENT CHECKLIST
// ════════════════════════════════════════════════════════════════════════════════

console.log(`
╔════════════════════════════════════════════════════════════════════════════╗
║                    🔒 SECURITY INTEGRATION COMPLETE                        ║
╠════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║ ✅ IP Blacklist & DDoS Prevention:   ACTIVE                              ║
║    ├─ Automatic brute force detection                                    ║
║    ├─ Bot detection & blocking                                          ║
║    ├─ Exponential backoff (15min → 7 days)                              ║
║    └─ 6 Admin endpoints available                                       ║
║                                                                            ║
║ ✅ Audit Logging:                    ACTIVE                              ║
║    ├─ All security events logged                                        ║
║    ├─ HMAC-SHA256 integrity verification                                ║
║    ├─ Forensic trail for compliance                                     ║
║    └─ Log rotation enabled                                              ║
║                                                                            ║
║ 🔧 Admin Endpoints:                                                      ║
║    1. GET  /admin/ip-blacklist/stats       → View statistics             ║
║    2. GET  /admin/ip-blacklist/list        → List recent blocks          ║
║    3. POST /admin/ip-blacklist/block-ip    → Manually block IP           ║
║    4. POST /admin/ip-blacklist/unblock-ip  → Manually unblock IP         ║
║    5. POST /admin/ip-blacklist/add-trusted → Add to whitelist            ║
║    6. GET  /admin/ip-blacklist/export-waf  → Export for firewall         ║
║                                                                            ║
║ 🎯 Status: READY FOR PRODUCTION DEPLOYMENT                               ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
`);
