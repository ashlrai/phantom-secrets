#!/usr/bin/env node

import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  accessSync,
  constants,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { createInterface } from "node:readline";
import { validatePhantomDoSchema } from "./mcp-schema-contract.mjs";

const binaryPath = process.argv[2];
const expectedToolCount = Number(process.argv[3] ?? "54");
const registryPath = process.argv[4] ?? "mcp-registry/server.json";
const writeRegistry = process.argv[5] === "--write-registry";
if (
  !binaryPath ||
  process.argv.length > 6 ||
  (process.argv[5] && !writeRegistry) ||
  !Number.isSafeInteger(expectedToolCount) ||
  expectedToolCount < 1
) {
  throw new Error(
    "usage: mcp-stdio-smoke.mjs <phantom-mcp-binary> [expected-tool-count] [registry-path] [--write-registry]"
  );
}
accessSync(binaryPath, constants.X_OK);

const child = spawn(binaryPath, [], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env, NO_COLOR: "1" },
});
const exitPromise = once(child, "exit");
const stderrChunks = [];
let stderrBytes = 0;
child.stderr.on("data", (chunk) => {
  if (stderrBytes < 64 * 1024) {
    stderrChunks.push(chunk);
    stderrBytes += chunk.length;
  }
});

const pending = new Map();
let protocolFailure;
const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
lines.on("line", (line) => {
  let message;
  try {
    message = JSON.parse(line);
  } catch (error) {
    protocolFailure = new Error(`non-JSON data on MCP stdout: ${error.message}`);
    return;
  }
  if (message.id !== undefined && pending.has(message.id)) {
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) {
      reject(new Error(`MCP error ${message.error.code}: ${message.error.message}`));
    } else {
      resolve(message.result);
    }
  }
});

let nextId = 1;
function send(message) {
  child.stdin.write(`${JSON.stringify(message)}\n`);
}

function request(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    send({ jsonrpc: "2.0", id, method, params });
  });
}

function withTimeout(promise, label, timeoutMs = 10_000) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
    }),
  ]).finally(() => clearTimeout(timer));
}

try {
  await withTimeout(
    request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "phantom-release-smoke", version: "1.0.0" },
    }),
    "MCP initialize"
  );
  send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
  const result = await withTimeout(request("tools/list"), "MCP tools/list");

  if (protocolFailure) {
    throw protocolFailure;
  }
  if (!result || !Array.isArray(result.tools)) {
    throw new Error("tools/list did not return a tools array");
  }
  if (result.tools.length !== expectedToolCount) {
    throw new Error(
      `expected ${expectedToolCount} MCP tools, received ${result.tools.length}`
    );
  }

  const names = result.tools.map((tool) => tool.name);
  if (new Set(names).size !== names.length) {
    throw new Error("tools/list contains duplicate tool names");
  }
  const phantomDo = result.tools.find((tool) => tool.name === "phantom_do");
  if (!phantomDo) {
    throw new Error("closed engineering tool phantom_do is missing");
  }
  validatePhantomDoSchema(phantomDo.inputSchema);

  const registry = JSON.parse(readFileSync(registryPath, "utf8"));
  if (writeRegistry) {
    registry.tools = result.tools;
    writeFileSync(registryPath, `${JSON.stringify(registry, null, 2)}\n`);
  } else if (!isDeepStrictEqual(registry.tools, result.tools)) {
    throw new Error(
      `${registryPath} tools differ from the runtime tools/list catalog; ` +
        "run this smoke with --write-registry after reviewing runtime effects"
    );
  }

  const readme = readFileSync("README.md", "utf8");
  const catalogStart = readme.indexOf("- **Conversation facade**");
  const catalogEnd = readme.indexOf("\n\nTools that write state", catalogStart);
  if (catalogStart < 0 || catalogEnd < 0) {
    throw new Error("README MCP catalog boundaries are missing");
  }
  const readmeNames = [
    ...new Set(
      readme
        .slice(catalogStart, catalogEnd)
        .match(/`(phantom_[a-z_]+)`/g)
        ?.map((match) => match.slice(1, -1)) ?? []
    ),
  ].sort();
  const runtimeNames = [...names].sort();
  if (!isDeepStrictEqual(readmeNames, runtimeNames)) {
    throw new Error(
      `README MCP catalog does not enumerate the exact ${expectedToolCount} runtime tools`
    );
  }

  child.stdin.end();
  const [code, signal] = await withTimeout(exitPromise, "MCP shutdown");
  if (code !== 0 || signal !== null) {
    throw new Error(`phantom-mcp exited with code=${code} signal=${signal}`);
  }
  console.log(
    `MCP stdio smoke passed: ${result.tools.length} unique tools, deeply closed phantom_do schema, exact registry parity, and complete README catalog${writeRegistry ? " (registry updated)" : ""}`
  );
} catch (error) {
  child.kill("SIGKILL");
  const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();
  if (stderr) {
    error.message += `\nphantom-mcp stderr:\n${stderr}`;
  }
  throw error;
}
