#!/usr/bin/env node
/* global process, Buffer, console, URL, fetch, AbortSignal, AbortController, TextDecoder, setTimeout, clearTimeout */
/** Owner-OIDC Registry publication for io.github.ashlrai/phantom-secrets-mcp.
 * Manifest path: mcp-registry/server.json. Its version field is the package version.
 * No package installation or source execution. Authentication is the Actions OIDC channel only.
 */
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { mkdtemp, mkdir, chmod, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

export const SERVER = 'io.github.ashlrai/phantom-secrets-mcp';
export const PACKAGE = 'phantom-secrets-mcp';
export const REGISTRY = 'https://registry.modelcontextprotocol.io';
export const PUBLISHER = Object.freeze({
  version: '1.8.1',
  archive: 'mcp-publisher_linux_amd64.tar.gz',
  sha256: 'a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc',
  checksumsSha256: 'f7937a7908096f63147658e13f0f63a393a1c9fc722a2d10017593940d36e59e',
});
const SHA = /^[a-f0-9]{64}$/;
const REVISION = /^[a-f0-9]{40}$/;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const RELEASE_TAG = /^refs\/tags\/v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const INTEGRITY = /^sha512-[A-Za-z0-9+/]{86}==$/;
const shutdown = new AbortController();
const hash = (bytes, algorithm = 'sha256') => createHash(algorithm).update(bytes).digest('hex');
const fail = (reason) => { throw new Error(reason); };
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
function exactKeys(value, keys, label) {
  if (!record(value) || !isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort())) fail(`Unexpected ${label} fields`);
}
function parseJson(bytes, label) {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail(`Invalid ${label} JSON`); }
}

export function inputsFromEnv(env) {
  const input = {
    version: env.INPUT_VERSION,
    sourceSha: env.INPUT_SOURCE_SHA,
    sourceManifestSha256: env.INPUT_SOURCE_MANIFEST_SHA256,
    payloadSha256: env.INPUT_PAYLOAD_SHA256,
    npmIntegrity: env.INPUT_NPM_INTEGRITY,
  };
  if (!VERSION.test(input.version ?? '') || !REVISION.test(input.sourceSha ?? '') ||
    !SHA.test(input.sourceManifestSha256 ?? '') || !SHA.test(input.payloadSha256 ?? '') ||
    !INTEGRITY.test(input.npmIntegrity ?? '') ||
    Buffer.from(input.npmIntegrity.slice(7), 'base64').toString('base64') !== input.npmIntegrity.slice(7)) fail('Invalid immutable release inputs');
  return input;
}

/** This repository's default branch is main. workflow_dispatch is admitted only there. */
export function assertWorkflow(env, head) {
  const ref = env.GITHUB_REF ?? '';
  const event = env.GITHUB_EVENT_NAME;
  const releaseTag = RELEASE_TAG.test(ref);
  const admitted =
    (event === 'workflow_dispatch' && ref === 'refs/heads/main') ||
    (event === 'release' && releaseTag) ||
    (event === 'push' && releaseTag);
  if (env.GITHUB_ACTIONS !== 'true' || env.RUNNER_ENVIRONMENT !== 'github-hosted' || env.RUNNER_OS !== 'Linux' ||
    env.GITHUB_REPOSITORY !== 'ashlrai/phantom-secrets' || !admitted ||
    !REVISION.test(env.GITHUB_SHA ?? '') || head !== env.GITHUB_SHA) fail('Publication requires ashlrai/phantom-secrets on a release tag, the release event, or a default-branch dispatch');
}

/** The only omitted source field is the unsupported tool catalog, never another identity field. */
export function qualifiedPayload(sourceBytes, input) {
  if (hash(sourceBytes) !== input.sourceManifestSha256) fail('Source manifest digest differs');
  const source = parseJson(sourceBytes, 'source manifest');
  const keys = ['$schema', 'name', 'title', 'description', 'websiteUrl', 'repository', 'version', 'packages'];
  exactKeys(source, [...keys, 'tools'], 'source manifest');
  if (!Array.isArray(source.tools) || source.tools.length === 0) fail('Source tool catalog is unavailable');
  const payload = Object.fromEntries(Object.entries(source).filter(([key]) => key !== 'tools'));
  exactKeys(payload.repository, ['url', 'source', 'subfolder'], 'source repository');
  if (payload.$schema !== 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json' ||
    payload.name !== SERVER || payload.version !== input.version || payload.title !== 'Phantom Secrets' ||
    typeof payload.description !== 'string' || !payload.description.trim() || [...payload.description].length > 100 ||
    payload.websiteUrl !== 'https://github.com/ashlrai/phantom-secrets' ||
    payload.repository.url !== 'https://github.com/ashlrai/phantom-secrets' || payload.repository.source !== 'github' ||
    payload.repository.subfolder !== 'crates/phantom-mcp' || !Array.isArray(payload.packages) || payload.packages.length !== 1) fail('Source identity differs');
  const pkg = payload.packages[0];
  exactKeys(pkg, ['registryType', 'registryBaseUrl', 'identifier', 'version', 'transport'], 'package');
  exactKeys(pkg.transport, ['type'], 'transport');
  if (pkg.registryType !== 'npm' || pkg.registryBaseUrl !== 'https://registry.npmjs.org' || pkg.identifier !== PACKAGE ||
    pkg.version !== input.version || pkg.transport.type !== 'stdio') fail('Package identity differs');
  const bytes = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`);
  if (hash(bytes) !== input.payloadSha256) fail('Supported-field payload digest differs');
  return { payload, bytes, sourceToolCount: source.tools.length };
}

/** 404 must be an official JSON problem response, never an HTML/network/permission guess. */
export function registryState(response, payload) {
  const body = parseJson(response.bytes, 'Registry');
  if (response.status === 404) {
    if (!record(body) || body.status !== 404 || typeof body.title !== 'string' || typeof body.detail !== 'string') fail('Unqualified Registry absence');
    return 'absent';
  }
  if (response.status !== 200 || !record(body)) fail('Registry read refused');
  const official = body._meta?.['io.modelcontextprotocol.registry/official'];
  if (!record(official) || official.status !== 'active' || !isDeepStrictEqual(body.server, payload)) fail('Existing Registry version differs or is inactive');
  return 'matching';
}

export function validateNpm(response, input) {
  if (response.status !== 200) fail('Published npm metadata is unavailable');
  const pkg = parseJson(response.bytes, 'npm');
  const tarball = `https://registry.npmjs.org/${PACKAGE}/-/${PACKAGE}-${input.version}.tgz`;
  if (pkg.name !== PACKAGE || pkg.version !== input.version || pkg.mcpName !== SERVER ||
    !record(pkg.dist) || pkg.dist.integrity !== input.npmIntegrity || pkg.dist.tarball !== tarball) fail('Published npm identity or integrity differs');
  return tarball;
}

/** Bounded anonymous HTTPS reads. Redirects allowed only for pinned GitHub release assets. */
export async function readPublic(url, limit = 1024 * 1024, fetcher = fetch) {
  const parsed = new URL(url);
  const githubAsset = parsed.hostname === 'github.com' && parsed.pathname.startsWith('/modelcontextprotocol/registry/releases/download/v1.8.1/');
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password ||
    !['raw.githubusercontent.com', 'registry.npmjs.org', 'registry.modelcontextprotocol.io', 'github.com'].includes(parsed.hostname)) fail('Unapproved public endpoint');
  const timeout = AbortSignal.any([AbortSignal.timeout(60_000), shutdown.signal]);
  const response = await fetcher(url, { redirect: githubAsset ? 'follow' : 'error', signal: timeout, headers: { Accept: 'application/json' } });
  if (githubAsset && response.url && !['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(new URL(response.url).hostname)) fail('Unapproved release redirect');
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > limit) { await response.body?.cancel(); fail('Public response too large'); }
  const parts = []; let size = 0;
  if (response.body) {
    const reader = response.body.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        size += value.byteLength;
        if (size > limit) { await reader.cancel(); fail('Public response too large'); }
        parts.push(value);
      }
    } finally { reader.releaseLock(); }
  }
  return { status: response.status, bytes: Buffer.concat(parts), sha256: hash(Buffer.concat(parts)) };
}

export async function preflight(input, read = readPublic) {
  const source = await read(`https://raw.githubusercontent.com/ashlrai/phantom-secrets/${input.sourceSha}/mcp-registry/server.json`);
  if (source.status !== 200) fail('Pinned source manifest unavailable');
  const qualified = qualifiedPayload(source.bytes, input);
  const metadata = await read(`https://registry.npmjs.org/${PACKAGE}/${input.version}`);
  const tarballUrl = validateNpm(metadata, input);
  const tarball = await read(tarballUrl, 64 * 1024 * 1024);
  if (tarball.status !== 200 || `sha512-${createHash('sha512').update(tarball.bytes).digest('base64')}` !== input.npmIntegrity) fail('Published npm bytes differ');
  const versionUrl = `${REGISTRY}/v0.1/servers/${encodeURIComponent(SERVER)}/versions/${input.version}?include_deleted=true`;
  const existing = await read(versionUrl);
  return { ...qualified, state: registryState(existing, qualified.payload), versionUrl,
    evidence: { sourceSha256: hash(source.bytes), payloadSha256: hash(qualified.bytes), npmMetadataSha256: hash(metadata.bytes), npmTarballSha256: hash(tarball.bytes), registryBeforeSha256: hash(existing.bytes) } };
}

/** Child output is deliberately discarded: authentication errors can contain tokens. */
export async function runCommand(bin, args, options = {}) {
  const { cwd, env, timeoutMs = 60_000, signal = shutdown.signal } = options;
  signal.throwIfAborted();
  return new Promise((resolvePromise, reject) => {
    const child = spawn(bin, args, { cwd, env, stdio: ['ignore', 'ignore', 'ignore'], detached: process.platform !== 'win32' });
    let timedOut = false;
    const kill = () => {
      try {
        if (process.platform === 'win32') child.kill('SIGKILL');
        else process.kill(-child.pid, 'SIGKILL');
      } catch { /* already exited */ }
    };
    const timer = setTimeout(() => { timedOut = true; kill(); }, timeoutMs);
    signal.addEventListener('abort', kill, { once: true });
    const cleanup = () => { clearTimeout(timer); signal.removeEventListener('abort', kill); };
    child.once('error', () => { cleanup(); reject(new Error('Owned command could not start')); });
    child.once('close', (code) => {
      cleanup();
      if (signal.aborted) reject(new Error('Owned command cancelled'));
      else if (timedOut) reject(new Error('Owned command timed out'));
      else if (code !== 0) reject(new Error(`Owned command failed (exit ${Number.isInteger(code) ? code : 'signal'})`));
      else resolvePromise();
    });
  });
}

export async function installPublisher(directory, read = readPublic, run = runCommand) {
  const base = `https://github.com/modelcontextprotocol/registry/releases/download/v${PUBLISHER.version}`;
  const checksums = await read(`${base}/registry_1.8.1_checksums.txt`, 16_384);
  if (checksums.status !== 200 || hash(checksums.bytes) !== PUBLISHER.checksumsSha256 ||
    !checksums.bytes.toString().split('\n').includes(`${PUBLISHER.sha256}  ${PUBLISHER.archive}`)) fail('Publisher checksum manifest differs');
  const archive = await read(`${base}/${PUBLISHER.archive}`, 16 * 1024 * 1024);
  if (archive.status !== 200 || hash(archive.bytes) !== PUBLISHER.sha256) fail('Publisher archive differs');
  const path = join(directory, 'publisher.tgz'); await writeFile(path, archive.bytes, { mode: 0o600, flag: 'wx' });
  // A pinned archive is trusted; extract only the known executable, no package hooks or source.
  await run('tar', ['-xzf', path, '-C', directory, '--no-same-owner', '--no-same-permissions', 'mcp-publisher'],
    { cwd: directory, env: { PATH: process.env.PATH, LANG: 'C.UTF-8', ...(process.env.RUNNER_TRACKING_ID ? { RUNNER_TRACKING_ID: process.env.RUNNER_TRACKING_ID } : {}) }, timeoutMs: 30_000 });
  const bin = join(directory, 'mcp-publisher'); await chmod(bin, 0o700);
  return bin;
}

export async function reconcile(versionUrl, payload, read = readPublic, wait = (ms) => new Promise(r => setTimeout(r, ms))) {
  // Read retries cover propagation only. They never reissue publish.
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (attempt) await wait(2_000);
    const response = await read(versionUrl);
    const state = registryState(response, payload);
    if (state === 'matching') return response;
  }
  fail('Publication not confirmed; reconcile exact version before any new publish');
}

async function confirmLatest(payload, read) {
  const latest = await read(`${REGISTRY}/v0.1/servers/${encodeURIComponent(SERVER)}/versions/latest?include_deleted=true`);
  if (registryState(latest, payload) !== 'matching' ||
    parseJson(latest.bytes, 'Registry')._meta['io.modelcontextprotocol.registry/official'].isLatest !== true) fail('Exact version exists, but latest is not the admitted version');
  return latest;
}

export async function publishRelease(input, env, dependencies = {}) {
  const read = dependencies.read ?? readPublic;
  const run = dependencies.run ?? runCommand;
  const install = dependencies.install ?? installPublisher;
  const wait = dependencies.wait;
  const initial = await preflight(input, read);
  if (initial.state === 'matching') {
    const latest = await confirmLatest(initial.payload, read);
    return { state: 'ALREADY_PUBLISHED_EXACT', ...initial.evidence, latestSha256: hash(latest.bytes), sourceToolCount: initial.sourceToolCount };
  }
  const directory = await mkdtemp(join(tmpdir(), 'phantom-secrets-registry-auth-'));
  let report;
  try {
    await chmod(directory, 0o700);
    const home = join(directory, 'home'); await mkdir(home, { mode: 0o700 });
    const config = join(home, '.config'); await mkdir(config, { mode: 0o700 });
    const commandEnv = { PATH: env.PATH, LANG: 'C.UTF-8', HOME: home, XDG_CONFIG_HOME: config, TMPDIR: directory,
      ...(env.RUNNER_TRACKING_ID ? { RUNNER_TRACKING_ID: env.RUNNER_TRACKING_ID } : {}) };
    const file = join(directory, 'server.json'); await writeFile(file, initial.bytes, { mode: 0o600, flag: 'wx' });
    const bin = await install(directory, read, run);
    await run(bin, ['validate', file], { cwd: directory, env: commandEnv });
    if (typeof env.ACTIONS_ID_TOKEN_REQUEST_TOKEN !== 'string' || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ||
      typeof env.ACTIONS_ID_TOKEN_REQUEST_URL !== 'string' || !env.ACTIONS_ID_TOKEN_REQUEST_URL) fail('Actions OIDC channel unavailable');
    // Authenticate only the official publisher, in its owned private HOME/cwd.
    await run(bin, ['login', 'github-oidc', `--registry=${REGISTRY}`], { cwd: directory,
      env: { ...commandEnv, ACTIONS_ID_TOKEN_REQUEST_TOKEN: env.ACTIONS_ID_TOKEN_REQUEST_TOKEN, ACTIONS_ID_TOKEN_REQUEST_URL: env.ACTIONS_ID_TOKEN_REQUEST_URL }, timeoutMs: 60_000 });
    await run(bin, ['validate', file], { cwd: directory, env: commandEnv });
    // Recheck every immutable source/npm/payload and exact Registry absence after login.
    const final = await preflight(input, read);
    if (!initial.bytes.equals(final.bytes) || hash(await readFile(file)) !== input.payloadSha256) fail('Publication inputs changed after authentication');
    if (final.state === 'matching') {
      const latest = await confirmLatest(final.payload, read);
      return { state: 'ALREADY_PUBLISHED_EXACT', ...final.evidence, latestSha256: hash(latest.bytes), sourceToolCount: final.sourceToolCount };
    }
    if (hash(await readFile(file)) !== input.payloadSha256) fail('Sealed payload changed');
    let publishCommand = 'success';
    try { await run(bin, ['publish', file], { cwd: directory, env: commandEnv, timeoutMs: 120_000 }); }
    catch { publishCommand = 'uncertain'; }
    const confirmed = await reconcile(final.versionUrl, final.payload, read, wait);
    const latest = await confirmLatest(final.payload, read);
    report = { state: 'PUBLISHED_EXACT_CONFIRMED', ...final.evidence, registryAfterSha256: hash(confirmed.bytes), latestSha256: hash(latest.bytes), publishCommand, sourceToolCount: final.sourceToolCount };
    return report;
  } finally {
    // Only this newly-created directory is removed; no ambient saved token is read or touched.
    await rm(directory, { recursive: true, force: true });
  }
}

export async function main(env = process.env) {
  const head = await new Promise((resolveHead, reject) => {
    const child = spawn('git', ['rev-parse', 'HEAD'], { stdio: ['ignore', 'pipe', 'ignore'] }); let out = '';
    child.stdout.on('data', chunk => { out += chunk; });
    child.once('error', reject); child.once('close', code => code === 0 ? resolveHead(out.trim()) : reject(new Error('Checkout identity unavailable')));
  });
  assertWorkflow(env, head);
  const input = inputsFromEnv(env);
  const report = await publishRelease(input, env);
  // Hash-only public evidence: never child output, raw token, or private HOME.
  console.log(JSON.stringify({ ...report, checkoutSha: head, phantomSourceSha: input.sourceSha, version: input.version, publisherVersion: PUBLISHER.version }));
}

/** Normal operator cancellation settles owned child groups before private credential cleanup. */
export async function withOwnedCancellation(action) {
  const cancel = () => shutdown.abort();
  process.on('SIGTERM', cancel); process.on('SIGINT', cancel);
  try { return await action(); }
  finally { process.off('SIGTERM', cancel); process.off('SIGINT', cancel); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) fail('This command takes release inputs from the trusted workflow environment only');
  withOwnedCancellation(() => main()).catch(() => { console.error('Registry publication held. Review immutable inputs and exact public readback before retrying.'); process.exitCode = 1; });
}
