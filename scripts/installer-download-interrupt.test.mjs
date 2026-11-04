import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const installers = {
  repository: join(repo, 'scripts', 'install.sh'),
  public: join(repo, 'apps', 'web', 'public', 'install.sh'),
};

// Complements installer-download-failure.test.mjs (curl exits nonzero): here
// the installer is terminated mid-download. The EXIT/TERM trap must still
// remove the private staging tree and release the lock, and the exit status
// must be the conventional 128+15.
for (const [name, installer] of Object.entries(installers)) {
  test(`${name} installer removes its staging directory when terminated during a download`, async (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-download-interrupt-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const shims = join(root, 'shims');
    const home = join(root, 'home');
    const install = join(root, 'live', 'bin');
    const started = join(root, 'curl.started');
    for (const dir of [shims, home, install]) mkdirSync(dir, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
    // The shim reports its staging output path, then lingers briefly so the
    // signal lands while the download is in flight.
    writeFileSync(join(shims, 'curl'), `#!/bin/sh
case "$*" in *--help*) exit 0 ;; esac
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--output" ]; then out="$2"; fi
  shift
done
printf '%s\\n' "$out" > "$PHANTOM_TEST_CURL_STARTED"
sleep 2
exit 22
`);
    chmodSync(join(shims, 'curl'), 0o755);

    const env = { ...process.env };
    for (const key of [
      'PHANTOM_REPO', 'PHANTOM_TAG', 'PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES',
      'PHANTOM_TEST_LOCAL_RELEASE_DIR', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    ]) delete env[key];
    const child = spawn('/bin/bash', [installer], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...env,
        HOME: home,
        SHELL: '/bin/bash',
        PATH: `${shims}:${process.env.PATH}`,
        PHANTOM_INSTALL_DIR: install,
        PHANTOM_TEST_CURL_STARTED: started,
      },
    });
    child.stdout.resume();
    child.stderr.resume();
    const exited = new Promise((done) => child.on('close', (code, signal) => done({ code, signal })));
    const killer = setTimeout(() => child.kill('SIGKILL'), 20000);
    t.after(() => clearTimeout(killer));

    for (let i = 0; i < 200 && !existsSync(started); i += 1) {
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.ok(existsSync(started), 'download must start before the signal is sent');
    const stage = dirname(dirname(readFileSync(started, 'utf8').trim()));
    assert.match(stage, /\.bin\.install\.[A-Za-z0-9]{6}$/);
    assert.ok(existsSync(stage), 'staging existed during the download');
    child.kill('SIGTERM');

    const { code, signal } = await exited;
    assert.equal(signal, null, 'installer handles SIGTERM itself');
    assert.equal(code, 143, 'terminated installer exits 128+SIGTERM');
    assert.equal(existsSync(stage), false, 'staging directory must be removed');
    assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
    assert.deepEqual(readdirSync(dirname(install)), ['bin'], 'no lock or staging leftovers');
  });
}
