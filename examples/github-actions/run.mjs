#!/usr/bin/env node
// CI recipe: prove the two steps in phantom-secret-gate.yml pass a clean pull
// request and fail one that adds a raw key, using a local git repository in
// place of GitHub. Usage: node examples/github-actions/run.mjs [--phantom /absolute/path/phantom]

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { FAKE_KEY, createSandbox, initProject, main, parseBinaryArgs, run } from "../_shared/sandbox.mjs";

const { phantom } = parseBinaryArgs(process.argv.slice(2), ["phantom"]);
const box = createSandbox("github-actions");
const git = (args, label = `git ${args[0]}`) => run(box, "git", args, { label });
const write = (name, content) => writeFileSync(join(box.workspace, name), content);
let base;

// A CI checkout: no local .env (it is gitignored), no vault, no hooks.
function checkout(branch) {
  git(["checkout", "-q", branch]);
  git(["reset", "-q", "--soft", base], "git reset --soft <base>");
}

process.exitCode = await main("GitHub Actions secret gate recipe", box, [
  ["a Phantom-protected main branch passes `phantom check`", () => {
    initProject(box, phantom);
    // Commit without the local hook so each CI step below is what decides.
    git(["add", "-A"]);
    git(["commit", "-q", "--no-verify", "-m", "base"], "git commit");
    base = git(["rev-parse", "HEAD"]).trim();
    run(box, phantom, ["check"], { label: "phantom check on main" });
  }],
  ["a clean pull request passes `phantom check --staged` against its base", () => {
    git(["checkout", "-q", "-b", "clean-pr"]);
    write("app.js", "export const client = new OpenAI({ baseURL: process.env.OPENAI_BASE_URL });\n");
    git(["add", "app.js"]);
    git(["commit", "-q", "--no-verify", "-m", "clean change"], "git commit");
    checkout("clean-pr");
    run(box, phantom, ["check", "--staged"], { label: "phantom check --staged (clean PR)" });
    git(["reset", "-q", "--hard", "clean-pr"], "git reset --hard");
  }],
  ["a pull request that hardcodes a key fails `phantom check --staged`", () => {
    git(["checkout", "-q", "-b", "leaky-pr", base]);
    write("leak.js", `export const key = "${FAKE_KEY}";\n`);
    git(["add", "leak.js"]);
    git(["commit", "-q", "--no-verify", "-m", "hardcoded key"], "git commit");
    checkout("leaky-pr");
    const out = run(box, phantom, ["check", "--staged"], { label: "phantom check --staged (leaky PR)", expectStatus: 1 });
    if (!out.includes("leak.js")) throw new Error("the failure did not name leak.js");
    git(["reset", "-q", "--hard", "leaky-pr"], "git reset --hard");
  }],
  ["a pull request that commits a raw dotenv value fails `phantom check`", () => {
    git(["checkout", "-q", "-b", "dotenv-pr", base]);
    write(".env.production", `OPENAI_API_KEY=${FAKE_KEY}\n`);
    git(["add", "-f", ".env.production"]);
    git(["commit", "-q", "--no-verify", "-m", "raw production env"], "git commit");
    const out = run(box, phantom, ["check"], { label: "phantom check (raw .env.production)", expectStatus: 1 });
    if (!out.includes("OPENAI_API_KEY")) throw new Error("the failure did not name OPENAI_API_KEY");
    if (out.includes(FAKE_KEY)) throw new Error("the failure printed the value");
  }],
]);
