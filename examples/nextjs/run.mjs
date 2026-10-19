#!/usr/bin/env node
// Next.js recipe: run a Next.js app under `phantom exec` and show the server
// sees a phm_ placeholder plus a local proxy URL, never the real value.
// Needs network for `npm install`. Usage: node examples/nextjs/run.mjs [--phantom /absolute/path/phantom]

import { spawn } from "node:child_process";
import { cpSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FAKE_KEY, Skip, assertKeyAbsent, createSandbox, filesUnder, initProject, main, parseBinaryArgs, run,
} from "../_shared/sandbox.mjs";

const { phantom } = parseBinaryArgs(process.argv.slice(2), ["phantom"]);
const box = createSandbox("nextjs");
const here = dirname(fileURLToPath(import.meta.url));
const freePort = () => new Promise((resolve) => {
  const s = createServer().listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); });
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

process.exitCode = await main("Next.js recipe", box, [
  ["phantom init protects the project's .env", () => {
    initProject(box, phantom);
    cpSync(here, box.workspace, { recursive: true, filter: (p) => !/node_modules|\.next|run\.mjs/.test(p) });
  }],
  ["the app installs and builds", () => {
    const opts = { cwd: box.workspace, env: { ...box.env, npm_config_cache: join(box.root, "npm-cache") }, encoding: "utf8", timeout: 600_000 };
    const install = spawnSyncOrSkip("npm", ["install", "--no-audit", "--no-fund"], opts);
    if (install.status !== 0) throw new Skip("npm install failed (network needed)");
    const build = spawnSyncOrSkip("npm", ["run", "build"], opts);
    if (build.status !== 0) throw new Error("next build failed (output withheld)");
  }],
  ["under phantom exec, the Next.js server sees a placeholder and a working local proxy", async () => {
    const port = await freePort();
    const child = spawn(phantom, ["exec", "--", "npx", "next", "start", "-p", String(port)], {
      cwd: box.workspace, env: box.env, stdio: "ignore",
    });
    try {
      let body;
      for (let i = 0; i < 60 && !body; i++) {
        await sleep(500);
        try { const res = await fetch(`http://127.0.0.1:${port}/api/status`); if (res.ok) body = await res.json(); } catch {}
      }
      if (!body) throw new Error("Next.js server never answered /api/status");
      if (!body.keyIsPlaceholder) throw new Error("server OPENAI_API_KEY is not a phm_ placeholder");
      if (!body.baseUrlIsLocalProxy) throw new Error("server OPENAI_BASE_URL is not the local proxy");
      if (!body.proxyHealthy) throw new Error("local proxy health check failed from the server");
      const html = await (await fetch(`http://127.0.0.1:${port}/`)).text();
      if (html.includes(FAKE_KEY)) throw new Error("rendered page contains the protected value");
    } finally {
      child.kill("SIGINT");
      await sleep(500);
      child.kill();
    }
  }],
  ["no readable file in the project holds the value", () => {
    assertKeyAbsent(filesUnder(box.workspace).filter((f) => !f.includes("node_modules")), box.workspace);
  }],
]);

import { spawnSync } from "node:child_process";
function spawnSyncOrSkip(cmd, args, opts) {
  const r = spawnSync(cmd, args, opts);
  if (r.error?.code === "ENOENT") throw new Skip(`${cmd} is not installed`);
  return r;
}
