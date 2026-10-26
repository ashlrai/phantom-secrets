#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { createInterface } from "node:readline";

// Installed-runtime companion to the static first-five-minutes contract. This
// intentionally does not run agent report: its cloud-login probe uses the OS
// keychain, which changing HOME does not isolate.
const args = process.argv.slice(2);
const binaries = { phantom: "phantom", mcp: "phantom-mcp" };
for (let index = 0; index < args.length; index += 2) {
  const option = args[index];
  const value = args[index + 1];
  if (!["--phantom", "--mcp"].includes(option) || !value || !isAbsolute(value)) {
    console.error("Usage: node run.mjs [--phantom <absolute-binary-path>] [--mcp <absolute-binary-path>]");
    process.exit(1);
  }
  binaries[option.slice(2)] = value;
}

const root = mkdtempSync(join(tmpdir(), "phantom-agent-smoke-"));
const workspace = join(root, "workspace");
const home = join(root, "home");
mkdirSync(workspace);
mkdirSync(home);
// Do not inherit provider keys, Phantom overrides, cloud tokens, or user config.
const env = {};
for (const key of ["PATH", "Path", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"]) {
  if (process.env[key]) env[key] = process.env[key];
}
Object.assign(env, {
  HOME: home, USERPROFILE: home, APPDATA: home, LOCALAPPDATA: home,
  XDG_CONFIG_HOME: home, XDG_DATA_HOME: home, XDG_STATE_HOME: home,
  XDG_CACHE_HOME: home, TMPDIR: root, TMP: root, TEMP: root,
  GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: join(home, ".gitconfig"),
  GIT_CEILING_DIRECTORIES: root,
  NO_COLOR: "1",
});
let skipped = 0;
function check(condition, message) {
  if (!condition) throw new Error(message);
}
function cli(binary, arguments_, label) {
  const result = spawnSync(binary, arguments_, {
    cwd: workspace, env, encoding: "utf8", timeout: 10_000,
    maxBuffer: 256 * 1024, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error?.code === "ENOENT") {
    console.log(`SKIP ${label}: executable unavailable; install the reviewed release or supply its absolute path`);
    skipped += 1;
    return null;
  }
  check(!result.error && result.status === 0 && !result.signal, `${label} failed (output withheld)`);
  return result.stdout.trim();
}

async function mcp(binary, arguments_, label) {
  const child = spawn(binary, arguments_, {
    cwd: workspace, env, windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
  });
  const lines = createInterface({ input: child.stdout });
  const pending = new Map();
  let sequence = 0;
  let protocolError;
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let closed = false;
  const close = new Promise((resolve) => child.once("close", () => { closed = true; resolve(); }));
  function rejectPending(message) {
    protocolError = new Error(message);
    for (const request of pending.values()) request.reject(protocolError);
    pending.clear();
  }
  child.on("error", () => rejectPending(`${label} could not start`));
  child.on("exit", () => rejectPending(`${label} exited before completion`));
  child.stdin.on("error", () => rejectPending(`${label} input transport failed`));
  child.stdout.on("data", (chunk) => {
    stdoutBytes += chunk.length;
    if (stdoutBytes > 1024 * 1024) { rejectPending(`${label} output limit exceeded`); child.kill(); }
  });
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > 256 * 1024) { rejectPending(`${label} diagnostic limit exceeded`); child.kill(); }
  });
  lines.on("line", (line) => {
    let message;
    try { message = JSON.parse(line); }
    catch { rejectPending(`${label} returned invalid JSON`); return; }
    if (!pending.has(message.id)) return;
    const request = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) request.reject(new Error(`${label} returned a protocol error (details withheld)`));
    else request.resolve(message.result);
  });
  function send(message) { child.stdin.write(`${JSON.stringify(message)}\n`); }
  async function request(method, params = {}) {
    if (protocolError) throw protocolError;
    const id = ++sequence;
    let timer;
    try {
      return await new Promise((resolve, reject) => {
        timer = setTimeout(() => { pending.delete(id); reject(new Error(`${label} ${method} timed out`)); }, 10_000);
        pending.set(id, { resolve, reject });
        send({ jsonrpc: "2.0", id, method, params });
      });
    } finally { clearTimeout(timer); }
  }
  function textResult(result) {
    check(result && !result.isError && Array.isArray(result.content), `${label} tool call failed`);
    return result.content.filter((item) => item.type === "text").map((item) => item.text).join("\n");
  }
  try {
    const initialized = await request("initialize", {
      protocolVersion: "2025-06-18", capabilities: {},
      clientInfo: { name: "phantom-agent-onboarding-smoke", version: "1.0.0" },
    });
    check(initialized?.serverInfo && initialized?.protocolVersion, `${label} initialization missing server identity`);
    send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
    const catalog = await request("tools/list");
    check(Array.isArray(catalog?.tools), `${label} missing tool catalog`);
    const names = catalog.tools.map((tool) => tool.name);
    check(new Set(names).size === names.length, `${label} duplicate tool names`);
    check(names.includes("phantom_status") && names.includes("phantom_capability"), `${label} missing onboarding tools`);
    const status = textResult(await request("tools/call", { name: "phantom_status", arguments: {} }));
    check(status.includes("not initialized"), `${label} did not recognize the empty fixture`);
    const capability = textResult(await request("tools/call", { name: "phantom_capability", arguments: {} }));
    let card;
    try { card = JSON.parse(capability); }
    catch { throw new Error(`${label} capability card is not JSON (contents withheld)`); }
    check(card.authority === "no_locus_seal", `${label} unexpected authority state`);
    check(card.hard_nos?.some((item) => item.verb === "secret_reveal"), `${label} missing secret-value boundary`);
    check(card.hard_nos?.some((item) => item.verb === "execute_engineering_action"), `${label} missing execution boundary`);
    check(!protocolError, `${label} transport failed`);
    console.log(`PASS ${label}: initialized, ${names.length} unique tools, empty-workspace status, no active Locus seal`);
  } finally {
    lines.close();
    child.stdin.end();
    const timer = setTimeout(() => { if (!closed) child.kill("SIGKILL"); }, 1_000);
    if (!closed) child.kill();
    await close;
    clearTimeout(timer);
  }
}

try {
  const version = cli(binaries.phantom, ["--version"], "Phantom CLI");
  if (version !== null) {
    check(/^phantom \d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(version), "Unexpected CLI version response");
    console.log(`PASS CLI version: ${version}`);
    const status = cli(binaries.phantom, ["status", "--oneline"], "CLI status");
    check(status === "not initialized", "CLI status did not recognize the empty fixture");
    console.log("PASS CLI status: empty workspace is not initialized");
    await mcp(binaries.phantom, ["mcp", "serve"], "embedded MCP");
  }
  const mcpVersion = cli(binaries.mcp, ["--version"], "standalone MCP");
  if (mcpVersion !== null) {
    check(/^phantom-mcp \d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(mcpVersion), "Unexpected MCP version response");
    console.log(`PASS standalone version: ${mcpVersion}`);
    await mcp(binaries.mcp, [], "standalone MCP");
    if (version !== null) check(version.slice(8) === mcpVersion.slice(12), "CLI and MCP versions differ");
  }
  check(readdirSync(workspace).length === 0 && readdirSync(home).length === 0,
    "Read-only checks unexpectedly changed fixture workspace or home");
  console.log("PASS isolation: fixture workspace and home remain empty");
  console.log("NOT TESTED: vault protection, proxy injection, client UI activation, providers, or deployment");
  console.log(skipped ? `INCOMPLETE: ${skipped} executable prerequisite(s) unavailable` : "COMPLETE: installed-runtime onboarding smoke passed");
  process.exitCode = skipped ? 2 : 0;
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  process.exitCode = 1;
} finally {
  // The sole deletion target is the exact disposable directory created above.
  rmSync(root, { recursive: true, force: true });
}
