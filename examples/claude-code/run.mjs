#!/usr/bin/env node
// Claude Code recipe: protect a project's .env, register Phantom as the
// project MCP server, and prove what the agent and the app each see.
// Usage: node examples/claude-code/run.mjs [--phantom /absolute/path/phantom]

import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
import {
  FAKE_KEY, assertKeyAbsent, createSandbox, filesUnder, initProject, main, mcpSession,
  parseBinaryArgs, readText, run, textOf,
} from "../_shared/sandbox.mjs";

const { phantom } = parseBinaryArgs(process.argv.slice(2), ["phantom"]);
const box = createSandbox("claude-code");
// The pre-commit hook `phantom init` installs calls `phantom` from PATH.
if (dirname(phantom) !== ".") box.env.PATH = `${dirname(phantom)}${process.platform === "win32" ? ";" : ":"}${box.env.PATH ?? box.env.Path ?? ""}`;
const ws = (...p) => join(box.workspace, ...p);
let mcpConfig;

process.exitCode = await main("Claude Code recipe", box, [
  ["phantom init replaces the real value in .env with a phm_ placeholder", () => {
    initProject(box, phantom);
    const dotenv = readText(ws(".env"));
    if (dotenv.includes(FAKE_KEY)) throw new Error(".env still holds the real value");
    if (!/^OPENAI_API_KEY=phm_[0-9a-f]+$/m.test(dotenv)) throw new Error(".env has no phm_ placeholder");
    if (!/^PORT=3000$/m.test(dotenv)) throw new Error("non-secret PORT was not preserved");
  }],
  ["phantom setup --client claude writes a project .mcp.json that runs `phantom mcp serve`", () => {
    run(box, phantom, ["setup", "--client", "claude"], { label: "phantom setup --client claude" });
    mcpConfig = JSON.parse(readText(ws(".mcp.json"))).mcpServers?.phantom;
    if (!mcpConfig || JSON.stringify(mcpConfig.args) !== JSON.stringify(["mcp", "serve"])) {
      throw new Error(".mcp.json has no phantom server with args [mcp, serve]");
    }
    if (!existsSync(ws("CLAUDE.md")) || !/phantom/i.test(readText(ws("CLAUDE.md")))) {
      throw new Error("CLAUDE.md has no Phantom instructions");
    }
  }],
  ["the MCP server Claude Code launches lists the secret by name, never by value", async () => {
    const session = await mcpSession(box, mcpConfig.command, mcpConfig.args, "phantom mcp serve");
    try {
      const { tools } = await session.request("tools/list");
      for (const name of ["phantom_list_secrets", "phantom_status", "phantom_capability"]) {
        if (!tools.some((t) => t.name === name)) throw new Error(`MCP catalog is missing ${name}`);
      }
      const listed = textOf(await session.callTool("phantom_list_secrets"));
      if (!listed.includes("OPENAI_API_KEY")) throw new Error("phantom_list_secrets did not name OPENAI_API_KEY");
      if (session.transcript().includes(FAKE_KEY)) throw new Error("an MCP response contained the protected value");
    } finally {
      await session.close();
    }
  }],
  ["phantom exec gives the app a placeholder plus a local proxy URL, not the value", () => {
    const probe = "const e=process.env;console.log(JSON.stringify({key:(e.OPENAI_API_KEY||'').slice(0,4),base:(e.OPENAI_BASE_URL||'').replace(/_phantom\\/.*$/,'_phantom/…'),leak:Object.values(e).some(v=>v.includes(process.argv[1]))}))";
    const out = run(box, phantom, ["exec", "--", process.execPath, "-e", probe, FAKE_KEY], { label: "phantom exec" });
    const line = out.split(/\r?\n/).find((l) => l.startsWith("{\"key\""));
    const seen = line && JSON.parse(line);
    if (!seen || seen.key !== "phm_") throw new Error("child OPENAI_API_KEY is not a phm_ placeholder");
    if (!/^http:\/\/127\.0\.0\.1:\d+\/openai\/_phantom\//.test(seen.base)) throw new Error("child has no local OPENAI_BASE_URL");
    if (seen.leak) throw new Error("the protected value reached the child environment");
    console.log(`     app saw OPENAI_API_KEY=phm_… and OPENAI_BASE_URL=${seen.base}`);
  }],
  ["no file an agent can read holds the value, and the project commits through the pre-commit hook", () => {
    assertKeyAbsent(filesUnder(box.workspace), box.workspace);
    run(box, "git", ["add", "-A"], { label: "git add" });
    run(box, "git", ["commit", "-q", "-m", "protected project"], { label: "git commit (runs phantom check --staged)" });
  }],
]);
