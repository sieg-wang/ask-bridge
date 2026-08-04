'use strict';

const assert = require('node:assert/strict');
const { existsSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const {
  artifactName,
  cargoTarget,
  platformKey,
  releaseBaseUrl,
  sha256,
  verifyBinaryFormat,
  verifyChecksum,
  verifyInstalledBinary,
} = require('../npm/postinstall.cjs');

test('maps supported platforms to Rust targets', () => {
  assert.equal(platformKey('darwin', 'arm64'), 'darwin-arm64');
  assert.equal(cargoTarget('darwin', 'arm64'), 'aarch64-apple-darwin');
  assert.equal(cargoTarget('darwin', 'x64'), 'x86_64-apple-darwin');
  assert.equal(cargoTarget('linux', 'x64'), 'x86_64-unknown-linux-gnu');
  assert.equal(cargoTarget('win32', 'x64'), 'x86_64-pc-windows-msvc');
});

test('rejects unsupported platforms', () => {
  assert.throws(() => cargoTarget('linux', 'arm'), /Unsupported platform/);
});

test('formats artifact names and release URLs', () => {
  assert.equal(artifactName('x86_64-unknown-linux-gnu'), 'ask-bridge-x86_64-unknown-linux-gnu.tar.xz');
  assert.equal(artifactName('x86_64-pc-windows-msvc'), 'ask-bridge-x86_64-pc-windows-msvc.zip');
  assert.equal(releaseBaseUrl('1.2.3'), 'https://github.com/doggy8088/ask-bridge/releases/download/v1.2.3');
});

// Recorded by the checksum test below so the next test can prove the fixture
// was removed. `node --test` runs the tests in this file in declaration order,
// and an `after` hook completes before the following test starts.
let checksumFixtureDir;

test('verifies sha256 checksums', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'ask-bridge-'));
  checksumFixtureDir = dir;
  // Runs even when the assertions below throw, so a failing run leaks nothing.
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'sample.txt');
  writeFileSync(file, 'hello');
  const digest = sha256(file);
  verifyChecksum(file, `${digest}  sample.txt`);
  assert.throws(() => verifyChecksum(file, '0'.repeat(64)), /Checksum mismatch/);
});

test('the checksum fixture never outlives its test', () => {
  // `npm test` runs on every install and in CI; a fixture directory per run
  // accumulates in the shared temp directory forever.
  assert.ok(
    checksumFixtureDir,
    'the checksum test must run first and record its fixture directory'
  );
  assert.equal(
    existsSync(checksumFixtureDir),
    false,
    `checksum fixture ${checksumFixtureDir} survived the test run`
  );
});

test('verifies native binary formats before installation', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ask-bridge-format-'));
  const windowsBinary = join(dir, 'ask-bridge.exe');
  const linuxBinary = join(dir, 'ask-bridge-linux');
  const macBinary = join(dir, 'ask-bridge-macos');

  writeFileSync(windowsBinary, Buffer.from([0x4d, 0x5a, 0x90, 0x00]));
  writeFileSync(linuxBinary, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  writeFileSync(macBinary, Buffer.from([0xcf, 0xfa, 0xed, 0xfe]));

  verifyBinaryFormat(windowsBinary, 'win32');
  verifyBinaryFormat(linuxBinary, 'linux');
  verifyBinaryFormat(macBinary, 'darwin');

  assert.throws(
    () => verifyBinaryFormat(macBinary, 'win32'),
    /binary format does not match win32/,
  );
  assert.throws(
    () => verifyBinaryFormat(windowsBinary, 'darwin'),
    /binary format does not match darwin/,
  );
});

test('rejects executable version output from a different program', () => {
  assert.throws(
    () => verifyInstalledBinary(process.execPath, process.platform),
    /unexpected version output/,
  );
});
