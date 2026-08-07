'use strict';

const assert = require('node:assert/strict');
const { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { EventEmitter } = require('node:events');
const { Readable } = require('node:stream');

const {
  DOWNLOAD_DEADLINE_MS,
  MAX_DOWNLOAD_BYTES,
  artifactName,
  cargoTarget,
  download,
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

// Same bookkeeping as `checksumFixtureDir` above, for the format fixture.
let formatFixtureDir;

test('verifies native binary formats before installation', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'ask-bridge-format-'));
  formatFixtureDir = dir;
  // Runs even when the assertions below throw, so a failing run leaks nothing.
  t.after(() => rmSync(dir, { recursive: true, force: true }));
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

test('the binary-format fixture never outlives its test', () => {
  // The twin of the checksum-fixture guard. This directory had no cleanup at
  // all until now: an upstream change reintroduced the bare `mkdtempSync` that
  // a local commit had already fixed, and because a leaked temp directory
  // breaks nothing, every test above stayed green while `npm test` -- which
  // runs on every install and in CI -- left one directory behind per run.
  assert.ok(
    formatFixtureDir,
    'the binary-format test must run first and record its fixture directory'
  );
  assert.equal(
    existsSync(formatFixtureDir),
    false,
    `binary-format fixture ${formatFixtureDir} survived the test run`
  );
});

test('rejects executable version output from a different program', () => {
  assert.throws(
    () => verifyInstalledBinary(process.execPath, process.platform),
    /unexpected version output/,
  );
});

// ---------------------------------------------------------------------------
// Download boundaries.
//
// `download` buffers the whole response in memory until `end`. Node's global
// HTTPS agent contributes a 5s *socket* timeout, which only fires on a
// connection that goes quiet -- it does nothing about a response that keeps
// dripping bytes, or one that is simply enormous. Both run unattended during
// `npm install`. These tests drive the `httpGet` seam because that is the only
// way to arrange either shape: a real server that drips forever is not
// something a unit test can stand up.

/** A fake `https.get` that answers with `body` and the given headers. */
function fakeGet(body, { statusCode = 200, headers = {} } = {}) {
  return (url, cb) => {
    const req = new EventEmitter();
    req.destroy = () => {};
    const res = Readable.from(body);
    res.statusCode = statusCode;
    res.headers = headers;
    setImmediate(() => cb(res));
    return req;
  };
}

test('a response over the byte ceiling is refused, and nothing is written', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ask-bridge-download-'));
  const destination = join(dir, 'artifact.bin');
  // One chunk past the ceiling, delivered as chunks so the running total is
  // what catches it rather than a single allocation.
  const chunk = Buffer.alloc(1024 * 1024);
  const chunks = (function* () {
    for (let sent = 0; sent <= MAX_DOWNLOAD_BYTES; sent += chunk.length) yield chunk;
  })();

  await assert.rejects(
    download('https://example.invalid/artifact.bin', destination, { httpGet: fakeGet(chunks) }),
    new RegExp(`exceeded the ${MAX_DOWNLOAD_BYTES}-byte ceiling`),
  );
  assert.equal(existsSync(destination), false, 'an over-ceiling download must leave no artifact');
  rmSync(dir, { recursive: true, force: true });
});

test('an oversized content-length is refused before the body is read', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ask-bridge-download-'));
  const destination = join(dir, 'artifact.bin');
  let bodyWasRead = false;
  const body = (function* () {
    bodyWasRead = true;
    yield Buffer.alloc(8);
  })();

  await assert.rejects(
    download('https://example.invalid/artifact.bin', destination, {
      httpGet: fakeGet(body, { headers: { 'content-length': String(MAX_DOWNLOAD_BYTES + 1) } }),
    }),
    /advertises \d+ bytes, over the/,
  );
  assert.equal(bodyWasRead, false, 'the advertised size must be refused before spending memory');
  assert.equal(existsSync(destination), false);
  rmSync(dir, { recursive: true, force: true });
});

// `timeout` so that a missing deadline is a *failure* rather than a hang: this
// test's whole subject is a response that never ends, so without it the
// mutation that removes the deadline blocks `npm test` forever instead of
// turning it red. That was measured, not assumed.
test('a response that never ends is cut off by the deadline', { timeout: 10_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ask-bridge-download-'));
  const destination = join(dir, 'artifact.bin');
  // Never emits `end` and never goes quiet: exactly the shape the socket
  // timeout cannot see.
  const stalled = new Readable({ read() {} });
  const httpGet = (url, cb) => {
    const req = new EventEmitter();
    req.destroy = (err) => stalled.destroy(err);
    stalled.statusCode = 200;
    stalled.headers = {};
    setImmediate(() => cb(stalled));
    return req;
  };

  await assert.rejects(
    download('https://example.invalid/artifact.bin', destination, {
      httpGet,
      deadlineAt: Date.now() + 50,
    }),
    /exceeded the \d+ms deadline/,
  );
  assert.equal(existsSync(destination), false);
  rmSync(dir, { recursive: true, force: true });
});

test('the deadline covers the whole redirect chain, not each hop', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ask-bridge-download-'));
  const destination = join(dir, 'artifact.bin');
  let hops = 0;
  const httpGet = (url, cb) => {
    const req = new EventEmitter();
    req.destroy = () => {};
    hops += 1;
    const res = Readable.from([Buffer.alloc(0)]);
    res.statusCode = 302;
    res.headers = { location: `https://example.invalid/hop-${hops}` };
    setImmediate(() => cb(res));
    return req;
  };

  // Already past the deadline: a per-hop deadline would restart the clock and
  // follow all five redirects.
  await assert.rejects(
    download('https://example.invalid/artifact.bin', destination, {
      httpGet,
      deadlineAt: Date.now() - 1,
    }),
    /exceeded the \d+ms deadline/,
  );
  assert.equal(hops, 0, 'an expired deadline must not issue a request at all');
  rmSync(dir, { recursive: true, force: true });
});

test('an ordinary download still writes exactly what arrived', async () => {
  // Anti-tautology: the bounds must not be reachable on a normal artifact.
  const dir = mkdtempSync(join(tmpdir(), 'ask-bridge-download-'));
  const destination = join(dir, 'artifact.bin');
  const payload = Buffer.from('ask-bridge release artifact');

  await download('https://example.invalid/artifact.bin', destination, {
    httpGet: fakeGet([payload], { headers: { 'content-length': String(payload.length) } }),
  });

  assert.deepEqual(readFileSync(destination), payload);
  assert.ok(DOWNLOAD_DEADLINE_MS > 0 && MAX_DOWNLOAD_BYTES > 0);
  rmSync(dir, { recursive: true, force: true });
});
