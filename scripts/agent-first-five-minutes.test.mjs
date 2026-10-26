import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = resolve(dirname(fileURLToPath(import.meta.url)), "../examples/agent-first-five-minutes/run.mjs");
function fixture(run) {
  const root = mkdtempSync(join(tmpdir(), "phantom-agent-smoke-test-"));
  try { return run(root); }
  finally { rmSync(root, { recursive: true, force: true }); }
}
function smoke(phantom, mcp) {
  return spawnSync(process.execPath, [script, "--phantom", phantom, "--mcp", mcp], {
    encoding: "utf8", timeout: 25_000, maxBuffer: 1024 * 1024,
  });
}
function fake(root, name, mode = "normal") {
  const path = join(root, name);
  // Only the protocol-harness fixtures use executable scripts. Native Windows
  // coverage comes from the real installed binaries in the acceptance matrix.
  writeFileSync(path, `#!/usr/bin/env node
const mode = ${JSON.stringify(mode)};
const role = ${JSON.stringify(name)};
if (process.argv.includes("--version")) {
  console.log(role === "phantom" ? "phantom 0.7.8" : "phantom-mcp " + (mode === "mismatch" ? "9.9.9" : "0.7.8"));
} else if (process.argv.includes("status")) {
  console.log("not initialized");
} else if (mode === "hang") {
  setInterval(() => {}, 1000);
} else if (mode === "malformed") {
  console.log("invalid transport data DO_NOT_ECHO_RAW_DIAGNOSTIC");
  setInterval(() => {}, 1000);
} else {
  require("node:readline").createInterface({ input: process.stdin }).on("line", line => {
    const request = JSON.parse(line);
    if (request.id === undefined) return;
    let result;
    if (request.method === "initialize") result = { protocolVersion: "2025-06-18", serverInfo: { name: "fixture", version: "0.7.8" } };
    else if (request.method === "tools/list") result = { tools: [{ name: "phantom_status" }, { name: "phantom_capability" }] };
    else if (request.params.name === "phantom_status") result = { content: [{ type: "text", text: "Phantom is not initialized in this directory." }] };
    else result = { content: [{ type: "text", text: JSON.stringify({ authority: "no_locus_seal", hard_nos: [{ verb: "secret_reveal" }, { verb: "execute_engineering_action" }] }) }] };
    console.log(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }));
  });
}
`, { mode: 0o700 });
  return path;
}

test("missing runtimes are incomplete, never passed", () => fixture(root => {
  const result = smoke(join(root, "missing-phantom"), join(root, "missing-mcp"));
  assert.equal(result.status, 2);
  assert.match(result.stdout, /INCOMPLETE: 2 executable prerequisite/);
  assert.doesNotMatch(result.stdout, /^COMPLETE:/m);
}));

test("unexpected executable version fails without dumping its output", () => fixture(root => {
  const result = smoke(process.execPath, join(root, "missing"));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unexpected CLI version response/);
}));

const unixFixture = { skip: process.platform === "win32" ? "executable-script harness is Unix-only; native Windows smoke uses real binaries" : false };

test("protocol harness can complete both runtime transports", unixFixture, () => fixture(root => {
  const result = smoke(fake(root, "phantom"), fake(root, "phantom-mcp"));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PASS embedded MCP/);
  assert.match(result.stdout, /PASS standalone MCP/);
  assert.match(result.stdout, /COMPLETE: installed-runtime onboarding smoke passed/);
}));

test("malformed MCP output fails and is withheld", unixFixture, () => fixture(root => {
  const result = smoke(fake(root, "phantom", "malformed"), fake(root, "phantom-mcp"));
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /invalid JSON/);
  assert.doesNotMatch(result.stdout + result.stderr, /DO_NOT_ECHO_RAW_DIAGNOSTIC/);
}));

test("hung MCP runtime times out and releases its subprocess", unixFixture, () => fixture(root => {
  const result = smoke(fake(root, "phantom", "hang"), fake(root, "phantom-mcp"));
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /initialize timed out/);
}));

test("mismatched CLI and MCP versions cannot complete", unixFixture, () => fixture(root => {
  const result = smoke(fake(root, "phantom"), fake(root, "phantom-mcp", "mismatch"));
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /CLI and MCP versions differ/);
  assert.doesNotMatch(result.stdout, /^COMPLETE:/m);
}));
