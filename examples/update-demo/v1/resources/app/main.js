// Fictional v1: renderer with Node.js integration.
const { BrowserWindow } = require("electron");
const win = new BrowserWindow({ webPreferences: { nodeIntegration: true } });
fetch("https://api.update-demo.example/v1/status");
