// ════════════════════════════════════════════════════════════════════
// ADMIN ROUTES INTEGRATION (ADD AFTER LINE 25 - IMPORTS SECTION)
// ════════════════════════════════════════════════════════════════════
const { initAdminRoutes } = require('./admin-routes');

// ════════════════════════════════════════════════════════════════════
// REGISTRATION STATE & WELCOME REDIRECT (ADD AFTER LINE 1076)
// ════════════════════════════════════════════════════════════════════

// GET /welcome - Post-registration success page
app.get('/welcome', createAccessTokenMiddleware({ state }), (req, res) => {
    try {
        const tokenFile = path.join(__dirname, 'pages', 'welcome.html');
        if (fs.existsSync(tokenFile)) {
            res.sendFile(tokenFile);
        } else {
            res.status(404).json({ error: 'Welcome page not found' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error loading welcome page' });
    }
});

// GET /pages/admin-dashboard.html - Admin dashboard (protected route)
app.get('/admin/dashboard', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        const dashFile = path.join(__dirname, 'pages', 'admin-dashboard.html');
        if (fs.existsSync(dashFile)) {
            res.sendFile(dashFile);
        } else {
            res.status(404).json({ error: 'Admin dashboard not found' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error loading admin dashboard' });
    }
});

// ════════════════════════════════════════════════════════════════════
// INITIALIZE REGISTRATION ROUTES WITH ADMIN INTEGRATION
// (ADD AFTER LINE 1163 - AFTER SSL/TLS HEALTH CHECK)
// ════════════════════════════════════════════════════════════════════

const { state: regState, whitelistCsvPath } = registerAccessRoutes(app, {
    logger: console,
    baseUrl: PROXY_BASE_URL,
    emailService,
    ipBlacklist: null,  // Optional: inject IP blacklist module if available
    auditLogger: null   // Optional: inject audit logger if available
});

// Store state globally for middleware access
const state = regState;

// ════════════════════════════════════════════════════════════════════
// INITIALIZE ADMIN ROUTES WITH DATABASE INTEGRATION
// (ADD AFTER REGISTRATION ROUTES)
// ════════════════════════════════════════════════════════════════════

initAdminRoutes(app, {
    logger: console,
    state: regState,
    whitelistCsvPath: whitelistCsvPath,
    emailService: emailService
});

console.log('✅ [ADMIN] Routes initialized - User, Blacklist, Devices, Security management enabled');

// ════════════════════════════════════════════════════════════════════
// WELCOME PAGE REDIRECT AFTER REGISTRATION COMPLETION
// (ADD AFTER REGISTRATION COMPLETION IN register.js completeVerification)
// This is already handled in register.js by setting accessToken cookie
// and the welcome.html page will check for valid token
// ════════════════════════════════════════════════════════════════════

// Redirect helper for post-registration
app.get('/registration-complete', createAccessTokenMiddleware({ state }), (req, res) => {
    res.redirect('/welcome');
});
