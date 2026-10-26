#!/usr/bin/env node
// Cursor recipe: protect a project's .env and register Phantom in Cursor's
// user-level ~/.cursor/mcp.json without clobbering servers already there.
// Usage: node examples/cursor/run.mjs [--phantom /absolute/path/phantom]

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  FAKE_KEY, assertKeyAbsent, createSandbox, filesUnder, initProject, main, mcpSession,
  parseBinaryArgs, readText, run, textOf,
} from "../_shared/sandbox.mjs";

const { phantom } = parseBinaryArgs(process.argv.slice(2), ["phantom"]);
const box = createSandbox("cursor");
const cursorConfig = join(box.home, ".cursor", "mcp.json");
const existing = { command: "npx", args: ["-y", "@example/other-mcp-server"] };
let server;

process.exitCode = await main("Cursor recipe", box, [
  ["phantom init protects the project's .env", () => {
    initProject(box, phantom);
    if (readText(join(box.workspace, ".env")).includes(FAKE_KEY)) throw new Error(".env still holds the real value");
  }],
  ["phantom setup --client cursor --print shows the snippet without writing anything", () => {
    const printed = run(box, phantom, ["setup", "--client", "cursor", "--print"], { label: "setup --print" });
    if (!printed.includes("\"phantom\"") || !printed.includes("\"serve\"")) throw new Error("printed snippet has no phantom server");
    if (filesUnder(box.home).some((f) => f.endsWith("mcp.json"))) throw new Error("--print wrote a config file");
  }],
  ["phantom setup --client cursor adds Phantom to ~/.cursor/mcp.json and keeps existing servers", () => {
    mkdirSync(join(box.home, ".cursor"), { recursive: true });
    writeFileSync(cursorConfig, `${JSON.stringify({ mcpServers: { other: existing } }, null, 2)}\n`);
    run(box, phantom, ["setup", "--client", "cursor"], { label: "phantom setup --client cursor" });
    const servers = JSON.parse(readText(cursorConfig)).mcpServers ?? {};
    server = servers.phantom;
    const other = servers.other ?? {};
    if (other.command !== existing.command || JSON.stringify(other.args) !== JSON.stringify(existing.args)) {
      throw new Error("the existing Cursor MCP server was changed");
    }
    if (!server || JSON.stringify(server.args) !== JSON.stringify(["mcp", "serve"])) throw new Error("no phantom server with args [mcp, serve]");
  }],
  ["the server Cursor launches answers phantom_status and names, not values, the secret", async () => {
    const session = await mcpSession(box, server.command, server.args, "phantom mcp serve");
    try {
      const status = textOf(await session.callTool("phantom_status"));
      if (!/OPENAI_API_KEY|1 secret|secrets?/i.test(status)) throw new Error("phantom_status did not describe the project");
      const listed = textOf(await session.callTool("phantom_list_secrets"));
      if (!listed.includes("OPENAI_API_KEY")) throw new Error("phantom_list_secrets did not name OPENAI_API_KEY");
      if (session.transcript().includes(FAKE_KEY)) throw new Error("an MCP response contained the protected value");
    } finally {
      await session.close();
    }
  }],
  ["neither the project nor Cursor's config holds the value", () => {
    // The encrypted-file vault lives under HOME too; it stores ciphertext, so
    // a plaintext search of every file is still a meaningful check.
    assertKeyAbsent([...filesUnder(box.workspace), ...filesUnder(box.home)], box.root);
  }],
]);
