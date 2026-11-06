import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnPosixSync } from './posix-spawn.mjs';

// Shared archive bytes and cleanup for the staging tests. Individual tests own
// their mktemp shims because they observe different properties of each call.
export function createStagingFixture(t, prefix) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const shims = join(root, 'shims');
  for (const dir of [fixture, payload, shims]) mkdirSync(dir);
  for (const name of ['phantom', 'phantom-mcp']) {
    writeFileSync(join(payload, name), `#!/bin/sh\necho "${name} 1.2.3"\n`);
    chmodSync(join(payload, name), 0o755);
  }
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const archive = `phantom-${arch}-${os}.tar.gz`;
  const result = spawnPosixSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr?.toString());
  const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
  writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);
  return { root, fixture, shims, archive };
}

// Record the hashed path while calculating the real digest, so failure tests
// can prove the installer populated the staging tree before cleaning it up.
export function installHashRecorders(root, shims) {
  const hashLog = join(root, 'hashed-paths');
  for (const tool of ['sha256sum', 'shasum']) {
    writeFileSync(join(shims, tool), `#!/usr/bin/env node
const { createHash } = require('node:crypto');
const { appendFileSync, readFileSync } = require('node:fs');
const target = process.argv.at(-1);
appendFileSync(${JSON.stringify(hashLog)}, target + '\\n');
const digest = createHash('sha256').update(readFileSync(target)).digest('hex');
process.stdout.write(digest + '  ' + target + '\\n');
`);
    chmodSync(join(shims, tool), 0o755);
  }
  return hashLog;
}
