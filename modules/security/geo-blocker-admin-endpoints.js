/**
 * ════════════════════════════════════════════════════════════════════════════════
 * GEO-BLOCKER ADMIN ENDPOINTS - Express Routes
 * ════════════════════════════════════════════════════════════════════════════════
 * 
 * Endpoints:
 * ✅ POST /admin/request-geo-bypass - Request bypass (user)
 * ✅ POST /admin/verify-geo-bypass - Verify code (user)
 * ✅ GET  /admin/geo-blocker/metrics - Admin stats
 * ✅ GET  /admin/geo-blocker/status - Service status
 * ✅ POST /admin/geo-blocker/revoke-bypass - Revoke bypass (admin)
 * ════════════════════════════════════════════════════════════════════════════════
 */

function registerGeoBlockerEndpoints(app, geoBlocker, geoBypass, validateApiKeyMiddleware) {
  /**
   * POST /admin/request-geo-bypass - Send verification code to email
   * User endpoint (no auth required - already blocked at middleware level)
   */
  app.post('/admin/request-geo-bypass', (req, res) => {
    try {
      const { email } = req.body;
      if (!email) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Email address required'
        });
      }

      const ip = geoBlocker.getRealIP(req);
      const geo = geoBlocker.getGeoLocation(ip);

      const result = geoBypass.sendBypassCode(email, ip, geo);
      
      if (!result.success) {
        return res.status(429).json({
          error: result.reason,
          message: result.message,
          retryAfterMs: result.retryAfterMs
        });
      }

      res.json({
        status: 'code_sent',
        message: result.message,
        expiresIn: result.expiresIn,
        nextStep: 'Check your email and submit the 6-digit code',
        endpoint: '/admin/verify-geo-bypass'
      });
    } catch (err) {
      console.error('[GEO-BLOCKER] Request bypass error:', err.message);
      res.status(500).json({
        error: 'Internal Server Error',
        detail: err.message
      });
    }
  });

  /**
   * POST /admin/verify-geo-bypass - Verify code and create bypass
   */
  app.post('/admin/verify-geo-bypass', (req, res) => {
    try {
      const { email, code } = req.body;
      if (!email || !code) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Email and code required'
        });
      }

      const ip = geoBlocker.getRealIP(req);
      const result = geoBypass.verifyBypassCode(email, code, ip);

      if (!result.valid) {
        return res.status(401).json({
          error: result.reason,
          message: result.message,
          attemptsRemaining: result.attemptsRemaining
        });
      }

      res.json({
        status: 'bypass_granted',
        message: result.message,
        bypassId: result.bypassId,
        validFor: result.bypassDuration,
        nextStep: 'You can now access admin resources from this location'
      });
    } catch (err) {
      console.error('[GEO-BLOCKER] Verify bypass error:', err.message);
      res.status(500).json({
        error: 'Internal Server Error',
        detail: err.message
      });
    }
  });

  /**
   * GET /admin/geo-blocker/metrics - View geolocking metrics (admin)
   */
  app.get('/admin/geo-blocker/metrics', validateApiKeyMiddleware, (req, res) => {
    try {
      if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Admin role required'
        });
      }

      const metrics = geoBlocker.getMetrics();
      res.json({
        status: 'ok',
        module: 'Geo-Blocker (Geographic Access Control)',
        ...metrics
      });
    } catch (err) {
      console.error('[GEO-BLOCKER] Metrics error:', err.message);
      res.status(500).json({
        error: 'Internal Server Error',
        detail: err.message
      });
    }
  });

  /**
   * GET /admin/geo-blocker/status - Service status (admin)
   */
  app.get('/admin/geo-blocker/status', validateApiKeyMiddleware, (req, res) => {
    try {
      if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Admin role required'
        });
      }

      const metrics = geoBlocker.getMetrics();
      res.json({
        status: 'operational',
        module: 'Geo-Blocker',
        timestamp: new Date().toISOString(),
        configuration: {
          blockedRegions: geoBlocker.config.blockedRegions,
          bypassDurationMinutes: geoBlocker.config.bypassDurationMinutes,
          cacheEnabled: true,
          cacheTTLSeconds: geoBlocker.CACHE_TTL / 1000,
          metricsEnabled: geoBlocker.config.enableMetrics
        },
        statistics: metrics,
        health: {
          activeBypasses: geoBlocker.bypasses.size,
          cacheSize: geoBlocker.geoCache.size,
          totalAttempts: Array.from(metrics.metrics.values()).reduce((sum, m) => sum + m.attempts, 0),
          totalBlocked: Array.from(metrics.metrics.values()).reduce((sum, m) => sum + m.blocks, 0)
        }
      });
    } catch (err) {
      console.error('[GEO-BLOCKER] Status error:', err.message);
      res.status(500).json({
        error: 'Internal Server Error',
        detail: err.message
      });
    }
  });

  /**
   * POST /admin/geo-blocker/revoke-bypass - Admin revoke bypass
   */
  app.post('/admin/geo-blocker/revoke-bypass', validateApiKeyMiddleware, (req, res) => {
    try {
      if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Admin role required'
        });
      }

      const { ip } = req.body;
      if (!ip) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'IP address required'
        });
      }

      geoBlocker.revokeBypass(ip);

      res.json({
        status: 'success',
        message: `Bypass revoked for IP ${ip}`,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('[GEO-BLOCKER] Revoke bypass error:', err.message);
      res.status(500).json({
        error: 'Internal Server Error',
        detail: err.message
      });
    }
  });
}

module.exports = { registerGeoBlockerEndpoints };
