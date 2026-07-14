// Hardened Path Validator - safe, small, production-ready
// - Uses fs.realpathSync to prevent symlink escapes
// - Exact path-component sensitive name checks (no substring false-positives)
// - Safe API: validateFilePath returns { ok, fullPath, reason }
// - isPathAllowed uses realpath checks

const fs = require('fs');
const path = require('path');

class PathValidator {
  constructor(opts = {}) {
    this.sensitiveNames = (opts.sensitiveNames || [
      '.env', '.git', '.ssh', '.aws', '.docker', 'kubernetes', 'secret', 'private', 'credential',
      'password', '.config', 'secrets', 'vault', 'cert', 'certificate', 'tls', 'ssl', 'pem',
      'jwk', 'oauth', 'token', 'apikey', 'access_token', 'refresh_token', 'session', 'cookie',
      'passwd', 'shadow', 'sudoers'
    ]).map(s => s.toLowerCase());

    // allow override for allowed dirs default (if caller doesn't pass one)
    this.defaultAllowedDirs = opts.allowedDirs || [path.join(__dirname, 'public')];
  }

  // Safe validator: returns object instead of throwing
  validateFilePath(userPath, baseDir) {
    try {
      if (!userPath || typeof userPath !== 'string') return { ok: false, reason: 'missing file path' };
      if (!baseDir || typeof baseDir !== 'string') return { ok: false, reason: 'missing base directory' };

      // Reject null bytes early
      if (userPath.indexOf('\0') !== -1) return { ok: false, reason: 'null byte in path' };

      // Decode URI components if present (safe-guard)
      let decoded = userPath;
      try { decoded = decodeURIComponent(userPath); } catch (_) { /* ignore decode errors */ }

      // Normalize and disallow absolute
      const normalized = path.posix.normalize(decoded.replace(/\\/g, '/'));
      if (path.isAbsolute(normalized)) return { ok: false, reason: 'absolute paths not allowed' };

      // Prevent traversal patterns in normalized form
      if (normalized.split('/').includes('..')) return { ok: false, reason: 'parent traversal detected' };

      // Resolve and use realpath to prevent symlink escape
      const resolvedBase = fs.realpathSync(baseDir);
      const combined = path.join(resolvedBase, normalized);

      let fullReal;
      try {
        fullReal = fs.realpathSync(combined);
      } catch (err) {
        // If file does not exist yet, resolve parent dir realpath and append last part
        const parent = path.dirname(combined);
        let parentReal;
        try { parentReal = fs.realpathSync(parent); }
        catch (e) { return { ok: false, reason: 'path does not exist' }; }
        fullReal = path.join(parentReal, path.basename(combined));
      }

      const resolvedBaseReal = resolvedBase;

      if (!(fullReal === resolvedBaseReal || fullReal.startsWith(resolvedBaseReal + path.sep))) {
        return { ok: false, reason: 'resolved path outside base directory' };
      }

      // Exact component sensitive name checks (case-insensitive)
      const parts = fullReal.split(path.sep).map(p => p.toLowerCase());
      for (const sens of this.sensitiveNames) {
        // If sens contains a path separator, check suffix match
        if (sens.includes(path.sep)) {
          if (fullReal.toLowerCase().endsWith(sens)) return { ok: false, reason: `access to sensitive path blocked (${sens})` };
        } else {
          if (parts.includes(sens)) return { ok: false, reason: `access to sensitive name blocked (${sens})` };
        }
      }

      // Additional defensive checks: reject suspicious characters that affect shells
      if (/[\x00\`\$\|;&<>]/.test(decoded)) return { ok: false, reason: 'suspicious characters in path' };

      return { ok: true, fullPath: fullReal };
    } catch (err) {
      return { ok: false, reason: 'validation error' };
    }
  }

  // Check if a path is within one of allowedDirs (uses realpath)
  isPathAllowed(filePath, allowedDirs = []) {
    if (!filePath || typeof filePath !== 'string') return false;
    if (!Array.isArray(allowedDirs) || allowedDirs.length === 0) allowedDirs = this.defaultAllowedDirs;

    let fileReal;
    try { fileReal = fs.realpathSync(filePath); }
    catch (_) { return false; }

    for (let d of allowedDirs) {
      try {
        const dReal = fs.realpathSync(d);
        if (fileReal === dReal || fileReal.startsWith(dReal + path.sep)) return true;
      } catch (e) { continue; }
    }

    return false;
  }
}

module.exports = new PathValidator();
