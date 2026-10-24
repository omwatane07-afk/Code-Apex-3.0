import { spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isWin = process.platform === 'win32';
const venvPythonWin = path.resolve(__dirname, '../../.venv/Scripts/python.exe');
const venvPythonUnix = path.resolve(__dirname, '../../.venv/bin/python');

const pythonExe = isWin
  ? (fs.existsSync(venvPythonWin) ? venvPythonWin : 'python')
  : (fs.existsSync(venvPythonUnix) ? venvPythonUnix : 'python3');

const backendDir = path.resolve(__dirname, '../../backend');

console.log(`[E2E SERVER] Starting production backend via ${pythonExe} on http://127.0.0.1:8000...`);

const child = spawn(
  pythonExe,
  ['-m', 'uvicorn', 'cyberq.api.app:app', '--host', '127.0.0.1', '--port', '8000'],
  {
    cwd: backendDir,
    env: {
      ...process.env,
      CYBERQ_ENV: 'pilot',
      PYTHONPATH: path.resolve(backendDir, 'src'),
    },
    stdio: 'inherit',
  }
);

process.on('SIGINT', () => child.kill('SIGINT'));
process.on('SIGTERM', () => child.kill('SIGTERM'));
process.on('exit', () => child.kill());
