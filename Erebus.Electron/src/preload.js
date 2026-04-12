const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('installer', {
  product: () => ipcRenderer.invoke('installer:product'),
  run: () => ipcRenderer.invoke('installer:run'),
});
