import { defineConfig } from '@playwright/test';
import { existsSync } from 'node:fs';
const python = process.env.LINKGUARD_PYTHON || (existsSync('../.venv/Scripts/python.exe') ? '../.venv/Scripts/python.exe' : existsSync('../.venv/bin/python') ? '../.venv/bin/python' : 'python');
const liveURL = process.env.LINKGUARD_BASE_URL;
export default defineConfig({
  testDir: './tests', workers: 1, timeout: 30000,
  use: { baseURL: liveURL || 'http://127.0.0.1:5187', channel: 'chrome', headless: true },
  webServer: liveURL ? undefined : { command: `"${python}" tests/preview_server.py`, url: 'http://127.0.0.1:5187/api/status', reuseExistingServer: false, timeout: 120000 },
});
