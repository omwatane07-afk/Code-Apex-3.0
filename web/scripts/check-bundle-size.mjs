import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const assetsDir = path.resolve(__dirname, '../dist/assets');

if (!fs.existsSync(assetsDir)) {
  console.error('Error: dist/assets directory does not exist. Run build first.');
  process.exit(1);
}

const files = fs.readdirSync(assetsDir);

// 1. Core index bundle gate: baseline 172.39 kB + 5% max = 181.01 kB
const indexFile = files.find(f => f.startsWith('index-') && f.endsWith('.js'));
if (!indexFile) {
  console.error('Error: index-*.js bundle not found in dist/assets');
  process.exit(1);
}

const indexPath = path.join(assetsDir, indexFile);
const indexStat = fs.statSync(indexPath);
const indexSizeKb = indexStat.size / 1024;
const indexGzipSizeKb = zlib.gzipSync(fs.readFileSync(indexPath)).length / 1024;

const BASELINE_KB = 172.39;
const MAX_CORE_KB = 181.01; // BASELINE_KB * 1.05

console.log(`[BUNDLE GATE] Core index bundle: ${indexFile}`);
console.log(`  Raw size: ${indexSizeKb.toFixed(2)} kB (Limit: ${MAX_CORE_KB.toFixed(2)} kB, Baseline: ${BASELINE_KB.toFixed(2)} kB, Growth: ${(((indexSizeKb - BASELINE_KB) / BASELINE_KB) * 100).toFixed(2)}%)`);
console.log(`  Gzip size: ${indexGzipSizeKb.toFixed(2)} kB`);

if (indexSizeKb > MAX_CORE_KB) {
  console.error(`FAILED: Core index bundle (${indexSizeKb.toFixed(2)} kB) exceeds 5% growth gate (${MAX_CORE_KB.toFixed(2)} kB)`);
  process.exit(1);
}

// 2. Three.js chunk gate: <= 250 kB gzip
const threeFile = files.find(f => f.startsWith('three-') && f.endsWith('.js'));
if (threeFile) {
  const threePath = path.join(assetsDir, threeFile);
  const threeStat = fs.statSync(threePath);
  const threeSizeKb = threeStat.size / 1024;
  const threeGzipSizeKb = zlib.gzipSync(fs.readFileSync(threePath)).length / 1024;
  const MAX_THREE_GZIP_KB = 250.0;

  console.log(`[BUNDLE GATE] Three.js chunk: ${threeFile}`);
  console.log(`  Raw size: ${threeSizeKb.toFixed(2)} kB`);
  console.log(`  Gzip size: ${threeGzipSizeKb.toFixed(2)} kB (Limit: ${MAX_THREE_GZIP_KB.toFixed(2)} kB)`);

  if (threeGzipSizeKb > MAX_THREE_GZIP_KB) {
    console.error(`FAILED: Three.js chunk gzip (${threeGzipSizeKb.toFixed(2)} kB) exceeds limit (${MAX_THREE_GZIP_KB.toFixed(2)} kB)`);
    process.exit(1);
  }
}

console.log('[BUNDLE GATE] PASSED: All bundle gates satisfied.');
