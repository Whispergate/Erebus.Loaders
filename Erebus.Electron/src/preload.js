const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('installer', {
  product: () => ipcRenderer.invoke('installer:product'),
  ready: () => ipcRenderer.invoke('installer:ready'),
  run: (token) => ipcRenderer.invoke('installer:run', token),
});
