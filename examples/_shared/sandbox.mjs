// Shared helpers for the client and CI recipes. Every recipe runs in a
// disposable workspace and HOME, with a fake, non-provider key and an
// explicit encrypted-file vault passphrase, so it never touches the real OS
// keychain, real client configs, or any provider. Nothing here is an OS
// sandbox: run only Phantom binaries you have verified.

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { createInterface } from "node:readline";

// Shaped like an OpenAI key so Phantom's detector protects it, but it is not a
// credential for any account. Recipes assert it never reaches a client
// config, agent-visible file, MCP response, or child process.
export const FAKE_KEY = `sk-proj-EXAMPLEONLY${"0".repeat(40)}`;

export function parseBinaryArgs(argv, names) {
  const binaries = Object.fromEntries(names.map((n) => [n, n === "mcp" ? "phantom-mcp" : "phantom"]));
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i]?.replace(/^--/, "");
    const value = argv[i + 1];
    if (!names.includes(name) || !value || !isAbsolute(value)) {
      console.error(`Usage: node run.mjs ${names.map((n) => `[--${n} <absolute-binary-path>]`).join(" ")}`);
      process.exit(1);
    }
    binaries[name] = value;
  }
  return binaries;
}

export function createSandbox(prefix) {
  const root = mkdtempSync(join(tmpdir(), `phantom-${prefix}-`));
  const home = join(root, "home");
  const workspace = join(root, "workspace");
  mkdirSync(home);
  mkdirSync(workspace);
  const env = {};
  for (const key of ["PATH", "Path", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"]) {
    if (process.env[key]) env[key] = process.env[key];
  }
  Object.assign(env, {
    HOME: home, USERPROFILE: home, APPDATA: home, LOCALAPPDATA: home,
    XDG_CONFIG_HOME: home, XDG_DATA_HOME: home, XDG_STATE_HOME: home, XDG_CACHE_HOME: home,
    TMPDIR: root, TMP: root, TEMP: root,
    GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: join(home, ".gitconfig"), GIT_CEILING_DIRECTORIES: root,
    GIT_AUTHOR_NAME: "Example", GIT_AUTHOR_EMAIL: "example@example.invalid",
    GIT_COMMITTER_NAME: "Example", GIT_COMMITTER_EMAIL: "example@example.invalid",
    NO_COLOR: "1",
    // Explicit encrypted-file vault inside the sandbox: no OS keychain access.
    PHANTOM_VAULT_PASSPHRASE: "example-only-vault-passphrase",
  });
  return { root, home, workspace, env, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

export class Skip extends Error {}

export function run(sandbox, binary, args, { label, expectStatus = 0, cwd } = {}) {
  const result = spawnSync(binary, args, {
    cwd: cwd ?? sandbox.workspace, env: sandbox.env, encoding: "utf8", timeout: 30_000,
    maxBuffer: 1024 * 1024, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error?.code === "ENOENT") throw new Skip(`${label}: ${binary} is not installed; supply its absolute path`);
  if (result.error || result.signal || result.status !== expectStatus) {
    throw new Error(`${label} exited ${result.status ?? result.signal ?? result.error?.code}, expected ${expectStatus} (output withheld)`);
  }
  return `${result.stdout}${result.stderr}`;
}

/** Initialize a git project with one fake secret and let `phantom init` protect it. */
export function initProject(sandbox, phantom) {
  run(sandbox, "git", ["init", "-q"], { label: "git init" });
  writeFileSync(join(sandbox.workspace, ".env"), `OPENAI_API_KEY=${FAKE_KEY}\nPORT=3000\n`);
  writeFileSync(join(sandbox.workspace, ".gitignore"), ".env\n");
  run(sandbox, phantom, ["init"], { label: "phantom init" });
}

export function readText(path) {
  return readFileSync(path, "utf8");
}

/** Every file under dir (skipping .git), for "the key is nowhere" checks. */
export function filesUnder(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    if (name === ".git") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...filesUnder(path));
    else out.push(path);
  }
  return out;
}

export function assertKeyAbsent(files, base) {
  for (const file of files) {
    let content;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (content.includes(FAKE_KEY)) throw new Error(`the protected value appeared in ${relative(base, file)}`);
  }
}

/** Minimal MCP stdio client: initialize, then call tools/list and tools/call. */
export async function mcpSession(sandbox, binary, args, label) {
  const child = spawn(binary, args, { cwd: sandbox.workspace, env: sandbox.env, windowsHide: true, stdio: ["pipe", "pipe", "ignore"] });
  const pending = new Map();
  let seq = 0;
  let transcript = "";
  const fail = (message) => {
    for (const p of pending.values()) p.reject(new Error(message));
    pending.clear();
  };
  child.on("error", (error) => fail(error.code === "ENOENT" ? "ENOENT" : `${label} could not start`));
  child.on("exit", () => fail(`${label} exited early`));
  createInterface({ input: child.stdout }).on("line", (line) => {
    transcript += `${line}\n`;
    let message;
    try { message = JSON.parse(line); } catch { return fail(`${label} wrote non-JSON to stdout`); }
    const p = pending.get(message.id);
    if (!p) return;
    pending.delete(message.id);
    clearTimeout(p.timer);
    if (message.error) p.reject(new Error(`${label} returned a JSON-RPC error`));
    else p.resolve(message.result);
  });
  const request = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++seq;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${label} ${method} timed out`)); }, 15_000);
    pending.set(id, { resolve, reject, timer });
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });
  try {
    await request("initialize", {
      protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "phantom-example-recipe", version: "0.0.0" },
    });
  } catch (error) {
    child.kill();
    if (error.message === "ENOENT") throw new Skip(`${label}: ${binary} is not installed`);
    throw error;
  }
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  return {
    request,
    callTool: (name, args = {}) => request("tools/call", { name, arguments: args }),
    transcript: () => transcript,
    close: () => new Promise((resolve) => {
      child.removeAllListeners("exit");
      child.once("close", resolve);
      child.stdin.end();
      setTimeout(() => child.kill(), 2_000).unref();
    }),
  };
}

export function textOf(result) {
  return (result?.content ?? []).map((c) => c.text ?? "").join("\n");
}

/** Run checks in order, print PASS lines, and exit 0 / 1 (fail) / 2 (skip). */
export async function main(title, sandbox, steps) {
  let passed = 0;
  try {
    for (const [name, step] of steps) {
      await step();
      passed += 1;
      console.log(`PASS ${name}`);
    }
    console.log(`COMPLETE: ${title} (${passed} checks)`);
    return 0;
  } catch (error) {
    if (error instanceof Skip) {
      console.log(`SKIP ${error.message}`);
      console.log(`INCOMPLETE: ${title}`);
      return 2;
    }
    console.log(`FAIL ${error.message}`);
    return 1;
  } finally {
    sandbox.cleanup();
  }
}
