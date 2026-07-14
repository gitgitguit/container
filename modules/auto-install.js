/**
 * AUTO-INSTALL (safer, deterministic, short)
 * - Verifies packages by resolution (require.resolve).
 * - Installs only missing packages (no shell interpolation).
 * - Uses spawnSync with timeout and --no-save to avoid modifying package.json.
 * - Simple lock to avoid concurrent installers.
 * - Returns false on any install failure so callers can decide to fail fast.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const PACKAGE_JSON = path.join(__dirname, '..', 'package.json');
const LOCK_FILE = path.join(os.tmpdir(), 'container-auto-install.lock');
const NPM_TIMEOUT_MS = 120000; // 2 minutes

function _tryAcquireLock() {
  try {
    const fd = fs.openSync(LOCK_FILE, 'wx');
    fs.writeSync(fd, `${process.pid}\n${Date.now()}\n`);
    fs.closeSync(fd);
    return true;
  } catch (err) {
    // If lock exists, someone else may be installing. Skip to avoid races.
    return false;
  }
}

function _releaseLock() {
  try { fs.unlinkSync(LOCK_FILE); } catch (_) { /* ignore */ }
}

function verifyPackageLoad(packageName) {
  try {
    require.resolve(packageName);
    return true;
  } catch (err) {
    return false;
  }
}

function _installPackage(pkg) {
  const args = ['install', pkg, '--no-save'];
  const res = spawnSync('npm', args, { stdio: 'inherit', timeout: NPM_TIMEOUT_MS });
  if (res.error) {
    console.error(`❌ [AUTO-INSTALL] npm spawn error for ${pkg}:`, res.error.message);
    return false;
  }
  if (res.status !== 0) {
    console.error(`❌ [AUTO-INSTALL] npm install exited with code ${res.status} for ${pkg}`);
    return false;
  }
  return true;
}

function ensurePackagesInstalled(requiredPackages = []) {
  if (!fs.existsSync(PACKAGE_JSON)) {
    console.warn('⚠️  [AUTO-INSTALL] package.json not found - skipping');
    return false;
  }

  if (!Array.isArray(requiredPackages) || requiredPackages.length === 0) {
    return true; // nothing required
  }

  // Acquire lock or skip if another process is installing
  const lockAcquired = _tryAcquireLock();
  if (!lockAcquired) {
    console.log('ℹ️  [AUTO-INSTALL] Installer busy in another process, verifying resolution only');
    // If we can't get lock, still verify resolution and return false if any missing
    const unresolved = requiredPackages.filter(p => !verifyPackageLoad(p));
    if (unresolved.length === 0) return true;
    console.warn(`⚠️  [AUTO-INSTALL] Missing packages (installer busy): ${unresolved.join(', ')}`);
    return false;
  }

  let anyFailed = false;
  try {
    for (const pkg of requiredPackages) {
      if (verifyPackageLoad(pkg)) continue;
      console.log(`⏳ [AUTO-INSTALL] Installing missing package: ${pkg}`);
      const ok = _installPackage(pkg);
      if (!ok) anyFailed = true;
      else console.log(`✅ [AUTO-INSTALL] ${pkg} installed`);
    }
  } finally {
    _releaseLock();
  }

  if (anyFailed) {
    console.error('❌ [AUTO-INSTALL] One or more packages failed to install');
    return false;
  }

  console.log('✅ [AUTO-INSTALL] All required packages verified/installed');
  return true;
}

function ensureGeoipInstalled() {
  if (verifyPackageLoad('geoip-lite')) {
    console.log('✅ [GEO-BLOCKER] geoip-lite already available');
    return true;
  }

  // Try to install (honors lock and returns precise failure)
  if (!_tryAcquireLock()) {
    console.warn('⚠️  [GEO-BLOCKER] Installer busy in another process - geoip-lite not guaranteed');
    return false;
  }

  let ok = false;
  try {
    console.log('⏳ [GEO-BLOCKER] Installing geoip-lite...');
    ok = _installPackage('geoip-lite');
    if (ok) console.log('✅ [GEO-BLOCKER] geoip-lite installed');
    else console.error('❌ [GEO-BLOCKER] geoip-lite install failed');
  } finally {
    _releaseLock();
  }

  return ok;
}

module.exports = {
  ensurePackagesInstalled,
  verifyPackageLoad,
  ensureGeoipInstalled
};
