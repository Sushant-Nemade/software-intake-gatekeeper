// Fictional v2: hardened renderer, but a new telemetry endpoint appears.
const { BrowserWindow } = require("electron");
const win = new BrowserWindow({ webPreferences: { contextIsolation: true, sandbox: true } });
fetch("https://api.update-demo.example/v2/status");
fetch("https://collect.metrics-collector.example/v1/events", { method: "POST" });
