#!/usr/bin/env node
'use strict';

const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} = require('node:fs');
const { get } = require('node:https');
const { join } = require('node:path');
const { URL } = require('node:url');

const PACKAGE_ROOT = join(__dirname, '..');
const BINARY_NAME = "ask-bridge";
const GITHUB_OWNER = "doggy8088";
const GITHUB_REPO = "ask-bridge";
const BIN_DIR = join(__dirname, `${BINARY_NAME}-bin`);
const BIN_NAME = process.platform === 'win32' ? `${BINARY_NAME}.exe` : BINARY_NAME;
const DEST = join(BIN_DIR, BIN_NAME);

const TARGETS = {
  'darwin-arm64': 'aarch64-apple-darwin',
  'darwin-x64': 'x86_64-apple-darwin',
  'linux-x64': 'x86_64-unknown-linux-gnu',
  'win32-x64': 'x86_64-pc-windows-msvc',
};

function platformKey(platform = process.platform, arch = process.arch) {
  return `${platform}-${arch}`;
}

function cargoTarget(platform = process.platform, arch = process.arch) {
  const target = TARGETS[platformKey(platform, arch)];
  if (!target) {
    throw new Error(`Unsupported platform: ${platform}/${arch}`);
  }
  return target;
}

function packageVersion() {
  return require(join(PACKAGE_ROOT, 'package.json')).version;
}

function artifactName(target) {
  const ext = target.includes('windows') || target.includes('pc-windows') ? 'zip' : 'tar.xz';
  return `${BINARY_NAME}-${target}.${ext}`;
}

function releaseBaseUrl(version = packageVersion()) {
  return `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/releases/download/v${version}`;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function verifyChecksum(filePath, checksumText) {
  const expected = checksumText.trim().split(/\s+/)[0].toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(expected)) {
    throw new Error('Invalid checksum file format');
  }
  const actual = sha256(filePath);
  if (actual !== expected) {
    throw new Error(`Checksum mismatch for ${filePath}: expected ${expected}, got ${actual}`);
  }
}

function verifyBinaryFormat(filePath, platform = process.platform) {
  const header = Buffer.alloc(4);
  const descriptor = openSync(filePath, 'r');
  let bytesRead;
  try {
    bytesRead = readSync(descriptor, header, 0, header.length, 0);
  } finally {
    closeSync(descriptor);
  }
  const binaryHeader = header.subarray(0, bytesRead);
  const magic = binaryHeader.toString('hex');
  const supportedMagic = {
    win32: ['4d5a'],
    linux: ['7f454c46'],
    darwin: [
      'feedface',
      'cefaedfe',
      'feedfacf',
      'cffaedfe',
      'cafebabe',
      'bebafeca',
      'cafebabf',
      'bfbafeca',
    ],
  };
  const expected = supportedMagic[platform];
  if (!expected) {
    throw new Error(`Unsupported platform for binary verification: ${platform}`);
  }
  if (!expected.some((prefix) => magic.startsWith(prefix))) {
    throw new Error(
      `Downloaded binary format does not match ${platform} (header: ${magic || 'empty'})`,
    );
  }
}

function verifyInstalledBinary(filePath, platform = process.platform) {
  verifyBinaryFormat(filePath, platform);
  const result = spawnSync(filePath, ['--version'], { encoding: 'utf8' });
  if (result.error) {
    throw new Error(`Installed binary could not start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = `${result.stdout || ''}${result.stderr || ''}`.trim();
    throw new Error(
      `Installed binary failed its version check with exit code ${result.status}${detail ? `: ${detail}` : ''}`,
    );
  }
  const output = `${result.stdout || ''}${result.stderr || ''}`.trim();
  if (!/^ask-bridge\s+\d+\.\d+\.\d+/.test(output)) {
    throw new Error(`Installed binary returned unexpected version output: ${output || '(empty)'}`);
  }
}

// Bounds on a download this script performs unattended, during `npm install`,
// with the whole response held in memory until `end`.
//
// Node's global HTTPS agent contributes a 5s *socket* timeout, which only fires
// on a connection that goes quiet. It says nothing about a response that keeps
// dripping bytes, or one that is simply enormous: either runs until the machine
// is out of memory, with no deadline to stop it. These two constants are that
// missing bound. The ceiling is far above any real release artifact (a Rust
// binary in a compressed archive, single-digit MB) so it is not a size limit in
// practice -- it is the point past which "this is the artifact" stops being a
// plausible reading of what is arriving.
const MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024;
const DOWNLOAD_DEADLINE_MS = 120_000;

// The deadline covers the whole chain, redirects included: a per-hop deadline
// with five redirects available is five times the bound it claims to be.
//
// `httpGet` is a seam, not configuration. These bounds are exactly the
// behaviour a test cannot observe without controlling the response -- a real
// server that drips forever or sends 200MB is not something a unit test can
// arrange -- and the tests are the only caller that ever passes it.
function download(url, destination, options = {}) {
  const {
    redirectsRemaining = 5,
    deadlineAt = Date.now() + DOWNLOAD_DEADLINE_MS,
    httpGet = get,
  } = options;
  return new Promise((resolve, reject) => {
    const budgetMs = deadlineAt - Date.now();
    if (budgetMs <= 0) {
      reject(new Error(`Download exceeded the ${DOWNLOAD_DEADLINE_MS}ms deadline: ${url}`));
      return;
    }

    let settled = false;
    let timer = null;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      fn(value);
    };

    const req = httpGet(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirectsRemaining > 0) {
        const nextUrl = new URL(res.headers.location, url).toString();
        res.resume();
        if (timer) clearTimeout(timer);
        timer = null;
        settled = true;
        download(nextUrl, destination, {
          redirectsRemaining: redirectsRemaining - 1,
          deadlineAt,
          httpGet,
        }).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        finish(reject, new Error(`Download failed ${res.statusCode}: ${url}`));
        return;
      }

      // Refuse on the advertised size before spending memory on it. A server
      // that lies here is still caught by the running total below.
      const advertised = Number(res.headers['content-length']);
      if (Number.isFinite(advertised) && advertised > MAX_DOWNLOAD_BYTES) {
        res.destroy();
        finish(reject, new Error(
          `Download advertises ${advertised} bytes, over the ${MAX_DOWNLOAD_BYTES}-byte ceiling: ${url}`,
        ));
        return;
      }

      const chunks = [];
      let received = 0;
      res.on('data', (chunk) => {
        received += chunk.length;
        if (received > MAX_DOWNLOAD_BYTES) {
          chunks.length = 0;
          res.destroy();
          finish(reject, new Error(
            `Download exceeded the ${MAX_DOWNLOAD_BYTES}-byte ceiling: ${url}`,
          ));
          return;
        }
        chunks.push(chunk);
      });
      res.on('error', (err) => finish(reject, err));
      res.on('end', () => {
        if (settled) return;
        writeFileSync(destination, Buffer.concat(chunks));
        finish(resolve, undefined);
      });
    });

    timer = setTimeout(() => {
      req.destroy(new Error(`Download exceeded the ${DOWNLOAD_DEADLINE_MS}ms deadline: ${url}`));
    }, budgetMs);

    req.on('error', (err) => finish(reject, err));
  });
}

function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Command failed: ${command}`);
}

function extract(archive, destDir) {
  mkdirSync(destDir, { recursive: true });
  if (archive.endsWith('.zip')) {
    if (process.platform === 'win32') {
      run('powershell', ['-NoProfile', '-Command', 'Expand-Archive', '-Force', '-Path', archive, '-DestinationPath', destDir]);
    } else {
      run('unzip', ['-o', archive, '-d', destDir]);
    }
  } else {
    run('tar', ['-xJf', archive, '-C', destDir]);
  }
}

function findExtractedBinary(dir, binName = BIN_NAME) {
  const direct = join(dir, binName);
  if (existsSync(direct)) return direct;

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const candidate = join(dir, entry.name, binName);
    if (existsSync(candidate)) return candidate;
  }

  throw new Error(`Archive did not contain ${binName}`);
}

function installFromLocalBuild() {
  const localRelease = join(PACKAGE_ROOT, 'target', 'release', BIN_NAME);
  if (!existsSync(localRelease)) return false;
  verifyBinaryFormat(localRelease);
  mkdirSync(BIN_DIR, { recursive: true });
  copyFileSync(localRelease, DEST);
  chmodSync(DEST, 0o755);
  verifyInstalledBinary(DEST);
  return true;
}

async function installFromRelease() {
  const target = cargoTarget();
  const archive = artifactName(target);
  const base = releaseBaseUrl();
  const tmpDir = join(BIN_DIR, '.tmp');
  const archivePath = join(tmpDir, archive);
  const checksumPath = `${archivePath}.sha256`;

  rmSync(tmpDir, { recursive: true, force: true });
  mkdirSync(tmpDir, { recursive: true });
  await download(`${base}/${archive}`, archivePath);
  await download(`${base}/${archive}.sha256`, checksumPath);
  verifyChecksum(archivePath, readFileSync(checksumPath, 'utf8'));
  extract(archivePath, tmpDir);

  const extracted = findExtractedBinary(tmpDir);
  verifyBinaryFormat(extracted);
  mkdirSync(BIN_DIR, { recursive: true });
  copyFileSync(extracted, DEST);
  chmodSync(DEST, 0o755);
  verifyInstalledBinary(DEST);
  rmSync(tmpDir, { recursive: true, force: true });
}

function checkChrome() {
  const chromePaths = {
    darwin: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    linux: '/usr/bin/google-chrome',
    win32: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  };
  const chromePath = chromePaths[process.platform];
  if (chromePath && !existsSync(chromePath)) {
    console.warn('');
    console.warn('⚠️  Google Chrome was not found on your system.');
    console.warn('   ask-bridge requires Chrome to automate ChatGPT / Gemini.');
    console.warn('   Please install it from: https://www.google.com/chrome/');
    console.warn('');
  }
}

async function main() {
  if (installFromLocalBuild()) return;
  await installFromRelease();
  checkChrome();
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = {
  DOWNLOAD_DEADLINE_MS,
  MAX_DOWNLOAD_BYTES,
  TARGETS,
  artifactName,
  cargoTarget,
  checkChrome,
  download,
  findExtractedBinary,
  platformKey,
  releaseBaseUrl,
  sha256,
  verifyBinaryFormat,
  verifyChecksum,
  verifyInstalledBinary,
};
