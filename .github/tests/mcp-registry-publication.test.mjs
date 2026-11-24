/* global process, Buffer, URL, setTimeout, clearTimeout, Response, AbortController */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile, access, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import {
  SERVER, PACKAGE, PUBLISHER, assertWorkflow, inputsFromEnv, qualifiedPayload,
  registryState, validateNpm, readPublic, preflight, publishRelease, installPublisher, runCommand,
} from '../scripts/publish-mcp-registry.mjs';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const bytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
const source = {
  $schema: 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json', name: SERVER,
  title: 'Phantom Secrets', description: 'Value-blind secret metadata for coding agents.',
  websiteUrl: 'https://github.com/ashlrai/phantom-secrets',
  repository: { url: 'https://github.com/ashlrai/phantom-secrets', source: 'github', subfolder: 'crates/phantom-mcp' },
  version: '0.7.9', tools: [{ name: 'metadata', description: 'Metadata only', inputSchema: { type: 'object' } }],
  packages: [{ registryType: 'npm', registryBaseUrl: 'https://registry.npmjs.org', identifier: PACKAGE, version: '0.7.9', transport: { type: 'stdio' } }],
};
const payload = Object.fromEntries(Object.entries(source).filter(([key]) => key !== 'tools'));
const tar = Buffer.from('immutable synthetic tar bytes, never extracted or executed');
const integrity = `sha512-${createHash('sha512').update(tar).digest('base64')}`;
const input = { version: '0.7.9', sourceSha: 'a'.repeat(40), sourceManifestSha256: sha(bytes(source)), payloadSha256: sha(bytes(payload)), npmIntegrity: integrity };
const env = { PATH: process.env.PATH, ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'not-a-real-token', ACTIONS_ID_TOKEN_REQUEST_URL: 'https://example.invalid/oidc' };
const workflowEnv = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'Linux', GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REPOSITORY: 'ashlrai/phantom-secrets', GITHUB_REF: 'refs/heads/main', GITHUB_SHA: 'b'.repeat(40) };
const releaseEnv = { INPUT_VERSION: input.version, INPUT_SOURCE_SHA: input.sourceSha, INPUT_SOURCE_MANIFEST_SHA256: input.sourceManifestSha256, INPUT_PAYLOAD_SHA256: input.payloadSha256, INPUT_NPM_INTEGRITY: input.npmIntegrity };
const reply = (status, value) => ({ status, bytes: bytes(value) });
const absent = () => reply(404, { title: 'Not Found', status: 404, detail: 'Version not found' });
const active = (server = payload, status = 'active') => reply(200, { server, _meta: { 'io.modelcontextprotocol.registry/official': { status, isLatest: true } } });
const npm = () => reply(200, { name: PACKAGE, version: input.version, mcpName: SERVER, dist: { integrity, tarball: `https://registry.npmjs.org/${PACKAGE}/-/${PACKAGE}-${input.version}.tgz` } });

function harness(options = {}) {
  const calls = []; let count = 0; let published = false; let authRoot; let privateHome;
  const read = async (url) => {
    calls.push(['read', url]);
    if (url.startsWith('https://raw.githubusercontent.com/')) return reply(200, options.changedSource && count > 0 ? { ...source, title: 'Changed' } : source);
    if (url.endsWith('.tgz')) return { status: 200, bytes: options.badTar ? Buffer.from('wrong') : tar };
    if (url.startsWith('https://registry.npmjs.org/')) return npm();
    if (url.includes('/versions/latest')) return options.latest ?? active();
    count += 1;
    return options.registry?.(count, published) ?? (published ? active() : absent());
  };
  const install = async (directory) => { authRoot = directory; return `${directory}/mcp-publisher`; };
  const run = async (_bin, args, opts) => {
    calls.push(['command', args[0], opts.env]); privateHome = opts.env.HOME;
    if (args[0] === 'login') {
      await writeFile(`${privateHome}/owned-token`, 'test token should be removed');
      if (options.loginFails) throw new Error('private token never reaches evidence');
      if (options.corruptPayload) await writeFile(`${authRoot}/server.json`, 'changed');
    }
    if (args[0] === 'publish') { published = !options.neverAppears; if (options.uncertain) throw new Error('uncertain transport'); }
  };
  return { read, run, install, wait: async () => {}, calls, root: () => authRoot, home: () => privateHome };
}

test('strict immutable input parsing and real dispatch identity', () => {
  assert.deepEqual(inputsFromEnv(releaseEnv), input);
  assert.doesNotThrow(() => assertWorkflow(workflowEnv, workflowEnv.GITHUB_SHA));
  assert.throws(() => assertWorkflow(workflowEnv, 'c'.repeat(40)));
});
for (const [key, value] of Object.entries({ INPUT_VERSION: '0.7.9;echo attack', INPUT_SOURCE_SHA: '../master', INPUT_SOURCE_MANIFEST_SHA256: 'x'.repeat(64), INPUT_PAYLOAD_SHA256: '', INPUT_NPM_INTEGRITY: 'sha512-' + 'A'.repeat(85) + 'B==' })) {
  test(`refuses malformed input ${key}`, () => assert.throws(() => inputsFromEnv({ ...releaseEnv, [key]: value })));
}
for (const [key, value] of Object.entries({ GITHUB_ACTIONS: 'false', RUNNER_ENVIRONMENT: 'self-hosted', RUNNER_OS: 'Windows', GITHUB_EVENT_NAME: 'pull_request_target', GITHUB_REPOSITORY: 'someone/phantom-secrets', GITHUB_REF: 'refs/heads/unreviewed', GITHUB_SHA: 'master' })) {
  test(`refuses unsupported workflow ${key}`, () => assert.throws(() => assertWorkflow({ ...workflowEnv, [key]: value }, workflowEnv.GITHUB_SHA)));
}
test('admits release tags, the release event, and default-branch dispatch only', () => {
  const tag = 'refs/tags/v0.8.10';
  assert.doesNotThrow(() => assertWorkflow({ ...workflowEnv, GITHUB_EVENT_NAME: 'release', GITHUB_REF: tag }, workflowEnv.GITHUB_SHA));
  assert.doesNotThrow(() => assertWorkflow({ ...workflowEnv, GITHUB_EVENT_NAME: 'push', GITHUB_REF: tag }, workflowEnv.GITHUB_SHA));
  assert.throws(() => assertWorkflow({ ...workflowEnv, GITHUB_REPOSITORY: 'ashlrai/ashlr-hub', GITHUB_REF: 'refs/heads/master' }, workflowEnv.GITHUB_SHA));
  assert.throws(() => assertWorkflow({ ...workflowEnv, GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF: tag }, workflowEnv.GITHUB_SHA));
  assert.throws(() => assertWorkflow({ ...workflowEnv, GITHUB_EVENT_NAME: 'release', GITHUB_REF: 'refs/heads/main' }, workflowEnv.GITHUB_SHA));
  assert.throws(() => assertWorkflow({ ...workflowEnv, GITHUB_EVENT_NAME: 'push', GITHUB_REF: 'refs/tags/not-a-release' }, workflowEnv.GITHUB_SHA));
});

test('source projection removes tools only; source and resulting bytes both pinned', () => {
  const qualified = qualifiedPayload(bytes(source), input);
  assert.deepEqual(qualified.payload, payload); assert.equal(qualified.sourceToolCount, 1);
  assert.deepEqual(qualified.bytes, bytes(payload));
  assert.throws(() => qualifiedPayload(bytes(source), { ...input, sourceManifestSha256: '0'.repeat(64) }));
  assert.throws(() => qualifiedPayload(bytes(source), { ...input, payloadSha256: '0'.repeat(64) }));
});
for (const update of [{ tools: [] }, { unexpected: true }, { name: 'io.github.someone/other' }, { packages: [] }]) {
  test(`refuses source shape ${Object.keys(update)[0]}`, () => {
    const altered = bytes({ ...source, ...update });
    assert.throws(() => qualifiedPayload(altered, { ...input, sourceManifestSha256: sha(altered) }));
  });
}
test('only structured exact404 admits new version; full matching active version admits no-op', () => {
  assert.equal(registryState(absent(), payload), 'absent'); assert.equal(registryState(active(), payload), 'matching');
  for (const bad of [reply(404, {}), reply(404, { title: 'Not Found', status: '404', detail: 'missing' }), reply(403, {}), { status: 404, bytes: Buffer.from('<html>missing</html>') }, active(payload, 'deleted'), active(payload, 'deprecated'), active({ ...payload, description: 'different' })]) {
    assert.throws(() => registryState(bad, payload));
  }
});
test('npm metadata namespace/integrity/tar URL each mandatory', () => {
  assert.match(validateNpm(npm(), input), /0\.7\.9\.tgz$/);
  const original = JSON.parse(npm().bytes);
  for (const update of [{ mcpName: 'other' }, { version: '0.6.0' }, { dist: { integrity, tarball: 'https://attacker.invalid/a.tgz' } }, { dist: { integrity: 'sha512-wrong', tarball: original.dist.tarball } }]) {
    assert.throws(() => validateNpm(reply(200, { ...original, ...update }), input));
  }
});
test('preflight hashes whole npm bytes, never installs or invokes package', async () => {
  const h = harness(); const result = await preflight(input, h.read);
  assert.equal(result.state, 'absent'); assert.equal(result.evidence.npmTarballSha256, sha(tar));
  assert.equal(h.calls.filter(c => c[0] === 'command').length, 0);
  await assert.rejects(preflight(input, harness({ badTar: true }).read), /bytes differ/);
});
test('readPublic bounds declared/chunked bytes and permits only anonymous HTTPS endpoints', async () => {
  const tooLong = async () => new Response('oversized', { headers: { 'content-length': '999' } });
  await assert.rejects(readPublic('https://registry.npmjs.org/a', 4, tooLong), /too large/);
  await assert.rejects(readPublic('https://registry.npmjs.org/a', 4, async () => new Response('oversized')), /too large/);
  let sent = false;
  await assert.rejects(readPublic('http://registry.npmjs.org/a', 4, async () => { sent = true; }), /Unapproved/);
  assert.equal(sent, false);
  let options;
  const response = await readPublic('https://registry.npmjs.org/a', 10, async (_url, opts) => { options = opts; return new Response('ok'); });
  assert.equal(response.bytes.toString(), 'ok'); assert.equal(options.redirect, 'error'); assert.deepEqual(options.headers, { Accept: 'application/json' });
});
test('publisher checksum failure cannot extract or execute an archive', async () => {
  let commands = 0;
  await assert.rejects(installPublisher('/unused', async () => reply(200, {}), async () => { commands += 1; }), /checksum/);
  assert.equal(commands, 0); assert.equal(PUBLISHER.version, '1.8.1'); assert.match(PUBLISHER.sha256, /^[a-f0-9]{64}$/);
});
test('already exact version causes no token exchange, install or publish', async () => {
  const h = harness({ registry: () => active() });
  const result = await publishRelease(input, {}, h);
  assert.equal(result.state, 'ALREADY_PUBLISHED_EXACT'); assert.equal(h.root(), undefined);
  assert.equal(h.calls.filter(c => c[0] === 'command').length, 0);
});
test('every already-published success branch requires exact active latest, without republishing', async () => {
  const notLatest = JSON.parse(active().bytes); notLatest._meta['io.modelcontextprotocol.registry/official'].isLatest = false;
  for (const registry of [() => active(), count => count === 1 ? absent() : active()]) {
    for (const latest of [active({ ...payload, version: '0.6.0' }), reply(200, notLatest), active(payload, 'deleted')]) {
      const h = harness({ registry, latest }); await assert.rejects(publishRelease(input, env, h));
      assert.equal(h.calls.filter(c => c[1] === 'publish').length, 0);
      if (h.root()) await assert.rejects(access(h.root()));
    }
  }
});
test('successful flow rechecks all inputs, authenticates only publisher and cleans real owned token HOME', async () => {
  const h = harness(); const result = await publishRelease(input, env, h);
  assert.equal(result.state, 'PUBLISHED_EXACT_CONFIRMED');
  const commands = h.calls.filter(c => c[0] === 'command');
  assert.deepEqual(commands.map(c => c[1]), ['validate', 'login', 'validate', 'publish']);
  for (const command of commands) {
    assert.equal(command[2].HOME, h.home());
    assert.equal(Object.hasOwn(command[2], 'ACTIONS_ID_TOKEN_REQUEST_TOKEN'), command[1] === 'login');
    assert.equal(Object.hasOwn(command[2], 'GITHUB_TOKEN'), false);
  }
  assert.equal(h.calls.filter(c => c[0] === 'read' && c[1].startsWith('https://raw.')).length, 2);
  await assert.rejects(access(h.root())); assert.ok(!JSON.stringify(result).includes(env.ACTIONS_ID_TOKEN_REQUEST_TOKEN));
});
test('version appears while authenticating: exact match no-op, never a second publish', async () => {
  const h = harness({ registry: count => count === 1 ? absent() : active() });
  assert.equal((await publishRelease(input, env, h)).state, 'ALREADY_PUBLISHED_EXACT');
  assert.equal(h.calls.filter(c => c[1] === 'publish').length, 0); await assert.rejects(access(h.root()));
});
for (const [label, options] of [['login failure', { loginFails: true }], ['changed source', { changedSource: true }], ['changed sealed payload', { corruptPayload: true }], ['inactive new record', { registry: count => count === 1 ? absent() : active(payload, 'deleted') }]]) {
  test(`${label} holds before publish and cleans owned token state`, async () => {
    const h = harness(options); await assert.rejects(publishRelease(input, env, h));
    assert.equal(h.calls.filter(c => c[1] === 'publish').length, 0); await assert.rejects(access(h.root()));
  });
}
test('uncertain publish reconciles successful actual record without retry POST', async () => {
  const h = harness({ uncertain: true }); const result = await publishRelease(input, env, h);
  assert.equal(result.publishCommand, 'uncertain'); assert.equal(result.state, 'PUBLISHED_EXACT_CONFIRMED');
  assert.equal(h.calls.filter(c => c[1] === 'publish').length, 1); await assert.rejects(access(h.root()));
});
test('unconfirmed publish or nonmatching latest remains held with no blind retry', async () => {
  const notLatest = JSON.parse(active().bytes); notLatest._meta['io.modelcontextprotocol.registry/official'].isLatest = false;
  for (const options of [{ neverAppears: true, uncertain: true }, { latest: active({ ...payload, version: '0.6.0' }) }, { latest: reply(200, notLatest) }]) {
    const h = harness(options); await assert.rejects(publishRelease(input, env, h));
    assert.equal(h.calls.filter(c => c[1] === 'publish').length, 1); await assert.rejects(access(h.root()));
  }
});
test('SIGTERM during real fake-native login settles child and removes its private credential directory', async () => {
  const module = new URL('../scripts/publish-mcp-registry.mjs', import.meta.url).href;
  const fakeNative = `#!${process.execPath}\nimport {writeFileSync} from 'node:fs';\nif(process.argv[2]==='login'){writeFileSync(process.env.HOME+'/owned-token','test-only');writeFileSync(process.env.HOME+'/child-pid',String(process.pid));setInterval(()=>{},1000);}`;
  const code = `import {publishRelease,withOwnedCancellation} from ${JSON.stringify(module)};import {writeFile,chmod} from 'node:fs/promises';
    const source=${JSON.stringify(source)},npm=${JSON.stringify(JSON.parse(npm().bytes))};
    const read=async url=>({status:url.includes('/versions/')?404:200,bytes:Buffer.from(url.endsWith('.tgz')?${JSON.stringify(tar.toString())}:JSON.stringify(url.includes('raw.githubusercontent')?source:url.includes('/versions/')?{title:'Not Found',status:404,detail:'missing'}:npm,null,2)+'\\n')});
    const install=async directory=>{const bin=directory+'/fake-native.mjs';await writeFile(bin,${JSON.stringify(fakeNative)},{mode:0o700});await chmod(bin,0o700);process.stdout.write(directory+'\\n');return bin;};
    withOwnedCancellation(()=>publishRelease(${JSON.stringify(input)},${JSON.stringify(env)},{read,install})).catch(()=>{process.exitCode=1;});`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; child.stdout.on('data', chunk => { output += chunk; });
  let stderr = ''; child.stderr.on('data', chunk => { stderr += chunk; });
  const finished = new Promise(resolveDone => child.once('close', (exit, signal) => resolveDone({ exit, signal })));
  let root; let pid; let timer;
  try {
    const end = Date.now() + 5_000;
    while (Date.now() < end) {
      root = output.trim();
      if (root) { try { pid = Number(await readFile(`${root}/home/child-pid`, 'utf8')); break; } catch { /* owned child has not written readiness yet */ } }
      await new Promise(r => setTimeout(r, 10));
    }
    assert.ok(pid > 0, `Fake native login did not reach readiness: ${stderr}`);
    child.kill('SIGTERM');
    const result = await Promise.race([finished, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Cancellation did not settle')), 5_000); })]);
    assert.equal(result.exit, 1); assert.equal(result.signal, null);
    await assert.rejects(access(root));
    assert.throws(() => process.kill(pid, 0), error => error.code === 'ESRCH');
  } finally {
    clearTimeout(timer);
    // Rescue only the exact test-owned processes if a regression fails; never leave a waiter.
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    if (pid) { try { process.kill(pid, 'SIGKILL'); } catch { /* gone */ } }
    if (root) await rm(root, { recursive: true, force: true });
  }
});
test('actual owned commands suppress secret output/errors and terminate on timeout or abort', async () => {
  await runCommand(process.execPath, ['-e', 'process.stdout.write("SECRET"); process.stderr.write("SECRET")']);
  await assert.rejects(runCommand(process.execPath, ['-e', 'console.error("SECRET");process.exit(2)']), error => !error.message.includes('SECRET') && /exit 2/.test(error.message));
  await assert.rejects(runCommand(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { timeoutMs: 30 }), /timed out/);
  const controller = new AbortController();
  const pending = runCommand(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { signal: controller.signal });
  controller.abort(); await assert.rejects(pending, /cancelled/);
});
test('workflow repository, release ref, default-branch dispatch, and job-scoped OIDC remain explicit', async () => {
  const workflow = await readFile(new URL('../workflows/publish-mcp-registry.yml', import.meta.url), 'utf8');
  const jobsAt = workflow.indexOf('\njobs:\n');
  const top = workflow.slice(0, jobsAt);
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /github\.repository == 'ashlrai\/phantom-secrets'/);
  assert.match(workflow, /github\.event_name == 'release' && startsWith\(github\.ref, 'refs\/tags\/v'\)/);
  assert.match(workflow, /github\.event_name == 'push' && startsWith\(github\.ref, 'refs\/tags\/v'\)/);
  assert.match(workflow, /github\.event_name == 'workflow_dispatch' && github\.ref == format\('refs\/heads\/\{0\}', github\.event\.repository\.default_branch\)/);
  assert.match(workflow, /id-token: write/);
  assert.match(top, /^permissions:\n  contents: read$/m);
  assert.doesNotMatch(top, /id-token/);
  assert.equal(workflow.match(/id-token:\s*write/g).length, 1);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /ref: \$\{\{ github\.sha \}\}/);
  assert.match(workflow, /node --test \.github\/tests\/mcp-registry-publication\.test\.mjs/);
  assert.match(workflow, /mcp-registry\/server\.json/);
  assert.doesNotMatch(workflow, /ashlrai\/ashlr-hub|refs\/heads\/master|pull_request_target:|self-hosted|npm (ci|install|publish)|secrets\.|run:.*\$\{\{ inputs/);
});
