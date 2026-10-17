#!/usr/bin/env node
// Local preview qualification for phm.dev source changes.
//
//   npm run preview:check    lint, typecheck, tests, credential-free build, verify, receipt
//   npm run preview:verify   verify an existing `next build` output only (used by CI)
//
// verify serves the built output on 127.0.0.1 and checks the publisher's
// route contract for "/" and "/secrets", security headers, retired installer
// paths, every sitemap page, every internal link and same-page anchor on those
// pages, and scans the shipped output for credential material.
//
// This never deploys. The receipt records local evidence for one exact source
// revision; promotion stays with protected merge and the host-owned website
// publisher (`ashlr_website_publish` in ashlrai/phantom).

import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  PUBLIC_ROUTE_CONTRACT,
  RETIRED_PATHS,
  checkRouteContract,
  credentialFindings,
  credentialFreeEnv,
  elementIds,
  fragmentLinks,
  internalLinks,
  missingSecurityHeaders,
  privateEnvironmentValues,
  sitemapPaths,
} from "./site-preview-contract.mjs";

const webDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const nextBin = join(webDir, "node_modules", ".bin", process.platform === "win32" ? "next.cmd" : "next");
const npmBin = process.platform === "win32" ? "npm.cmd" : "npm";
const RECEIPT_SCHEMA = "phm-site-preview/v1";

function git(...args) {
  try {
    return execFileSync("git", args, { cwd: webDir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

function sourceIdentity() {
  const status = git("status", "--porcelain=v1", "--untracked-files=all", "--", ".");
  return {
    commit: git("rev-parse", "HEAD"),
    tree: git("rev-parse", "HEAD:apps/web"),
    branch: git("rev-parse", "--abbrev-ref", "HEAD"),
    clean: status === "",
  };
}

function run(label, command, args, env) {
  return new Promise((resolveRun) => {
    const started = Date.now();
    process.stdout.write(`-> ${label}\n`);
    const child = spawn(command, args, { cwd: webDir, env, stdio: ["ignore", "inherit", "inherit"] });
    child.on("exit", (code) => resolveRun({ name: label, ok: code === 0, ms: Date.now() - started }));
    child.on("error", () => resolveRun({ name: label, ok: false, ms: Date.now() - started }));
  });
}

function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolvePort(port));
    });
  });
}

async function startServer(env) {
  const port = await freePort();
  const child = spawn(nextBin, ["start", "-H", "127.0.0.1", "-p", String(port)], {
    cwd: webDir,
    env: { ...env, NODE_ENV: "production" },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr = (stderr + chunk).slice(-4000);
  });
  const origin = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`next start exited: ${stderr.trim()}`);
    try {
      await fetch(origin, { redirect: "manual", signal: AbortSignal.timeout(2_000) });
      return { origin, stop: () => child.kill("SIGTERM") };
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  child.kill("SIGTERM");
  throw new Error("next start did not answer within 60 s");
}

async function get(origin, path) {
  const response = await fetch(new URL(path, origin), { redirect: "manual", signal: AbortSignal.timeout(20_000) });
  const contentType = response.headers.get("content-type") ?? "";
  const body = /text|xml|json/.test(contentType) ? await response.text() : (await response.arrayBuffer(), "");
  return { status: response.status, contentType, headers: response.headers, body };
}

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else if (entry.isFile()) yield path;
  }
}

/** Scan shipped output; also digest it so a receipt names the bytes it describes. */
function scanOutput(env) {
  const roots = [join(webDir, ".next", "static"), join(webDir, ".next", "server", "app"), join(webDir, "public")];
  const privateValues = privateEnvironmentValues(env);
  const findings = [];
  const digest = createHash("sha256");
  let files = 0;
  for (const root of roots) {
    if (!existsSync(root)) continue;
    for (const path of [...walk(root)].sort()) {
      if (statSync(path).size > 16 * 1024 * 1024) continue;
      const bytes = readFileSync(path);
      const name = relative(webDir, path).split("\\").join("/");
      digest.update(name).update("\0").update(bytes).update("\0");
      files += 1;
      if (!/\.(?:js|mjs|cjs|json|html|rsc|body|txt|xml|css|map|webmanifest|svg|sh|ps1)$/.test(path)) continue;
      for (const label of credentialFindings(bytes.toString("utf8"), privateValues)) findings.push(`${name}: ${label}`);
    }
  }
  return { files, digest: digest.digest("hex"), findings };
}

async function verify(env) {
  const problems = [];
  const routes = [];
  if (!existsSync(join(webDir, ".next", "BUILD_ID"))) throw new Error("No production build in .next; run `npm run build` first");
  const server = await startServer(env);
  try {
    const pages = new Map();
    for (const entry of PUBLIC_ROUTE_CONTRACT) {
      const page = await get(server.origin, entry.route);
      const contract = checkRouteContract(entry, page);
      const headers = missingSecurityHeaders(page.headers);
      routes.push({ route: entry.route, status: page.status, contract: contract.length === 0, missingHeaders: headers });
      for (const p of contract) problems.push(`${entry.route}: ${p}`);
      for (const h of headers) problems.push(`${entry.route}: missing ${h} header`);
      pages.set(entry.route, page);
    }
    for (const path of RETIRED_PATHS) {
      const { status } = await get(server.origin, path);
      if (status !== 410) problems.push(`${path}: status ${status}, expected 410`);
    }
    const sitemap = await get(server.origin, "/sitemap.xml");
    if (sitemap.status !== 200) problems.push(`/sitemap.xml: status ${sitemap.status}`);
    const listed = sitemapPaths(sitemap.body);
    for (const entry of PUBLIC_ROUTE_CONTRACT) if (!listed.includes(entry.route)) problems.push(`/sitemap.xml: missing ${entry.route}`);
    for (const path of listed) {
      if (pages.has(path)) continue;
      const page = await get(server.origin, path);
      if (page.status !== 200) problems.push(`sitemap ${path}: status ${page.status}`);
      if (page.contentType.includes("text/html")) pages.set(path, page);
    }
    const checked = new Map();
    let linkCount = 0;
    for (const [from, page] of pages) {
      const ids = elementIds(page.body);
      for (const fragment of fragmentLinks(page.body)) if (!ids.has(fragment)) problems.push(`${from}: href="#${fragment}" has no matching id`);
      for (const link of internalLinks(page.body)) {
        linkCount += 1;
        const [path, fragment] = link.split("#", 2);
        if (!checked.has(path)) {
          const target = pages.get(path) ?? (await get(server.origin, path));
          checked.set(path, target);
          // New pages join the Map being iterated, so the crawl covers every
          // internal page reachable from "/", "/secrets" and the sitemap.
          if (target.contentType.includes("text/html") && target.status === 200 && !pages.has(path)) pages.set(path, target);
        }
        const target = checked.get(path);
        if (target.status >= 400) problems.push(`${from}: link ${link} returns ${target.status}`);
        else if (fragment && target.status === 200 && target.contentType.includes("text/html") && !elementIds(target.body).has(fragment)) {
          problems.push(`${from}: link ${link} has no matching id on ${path}`);
        }
      }
    }
    const output = scanOutput(process.env);
    for (const finding of output.findings) problems.push(`credential material in output: ${finding}`);
    return { problems, routes, pagesChecked: pages.size, linksChecked: linkCount, output: { files: output.files, sha256: output.digest } };
  } finally {
    server.stop();
  }
}

function writeReceipt(path, receipt) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(receipt, null, 2)}\n`);
  process.stdout.write(`-> receipt ${relative(process.cwd(), path) || path}\n`);
}

async function main() {
  const [mode = "check", ...rest] = process.argv.slice(2);
  const receiptFlag = rest.indexOf("--receipt");
  const receiptPath = resolve(receiptFlag >= 0 ? rest[receiptFlag + 1] : join(webDir, ".next", "phm-site-preview-receipt.json"));
  if (!["check", "verify"].includes(mode)) {
    process.stderr.write("usage: site-preview.mjs check|verify [--receipt <path>]\n");
    process.exit(2);
  }
  const before = sourceIdentity();
  const env = credentialFreeEnv(process.env);
  const steps = [];
  if (mode === "check") {
    for (const [label, args] of [
      ["lint", ["run", "lint"]],
      ["typecheck", ["exec", "--", "tsc", "--noEmit"]],
      ["tests", ["test"]],
    ]) {
      steps.push(await run(label, npmBin, args, { ...process.env, ...env }));
    }
    steps.push(await run("credential-free production build", nextBin, ["build"], env));
  }
  let verification = null;
  if (steps.every((s) => s.ok)) {
    const started = Date.now();
    process.stdout.write("-> verify built routes, links and output\n");
    try {
      verification = await verify(env);
      steps.push({ name: "verify", ok: verification.problems.length === 0, ms: Date.now() - started });
    } catch (error) {
      verification = { problems: [error.message] };
      steps.push({ name: "verify", ok: false, ms: Date.now() - started });
    }
  }
  const after = sourceIdentity();
  const sourceStable = before.commit === after.commit && before.clean === after.clean;
  const ok = steps.length > 0 && steps.every((s) => s.ok) && sourceStable;
  const receipt = {
    schema: RECEIPT_SCHEMA,
    mode,
    ok,
    observedAt: new Date().toISOString(),
    source: { ...after, stableDuringRun: sourceStable },
    node: process.version,
    steps,
    verification,
    scope:
      "Local preview evidence only. Not CI admission, not a deployment, not promotion. " +
      "phm.dev changes ship through a reviewed PR, required checks, a protected merge to main, " +
      "and the commissioned host-owned website publisher.",
  };
  writeReceipt(receiptPath, receipt);
  for (const problem of verification?.problems ?? []) process.stdout.write(`!  ${problem}\n`);
  if (!after.clean) process.stdout.write("warn source has uncommitted changes; the receipt cannot describe a commit\n");
  process.stdout.write(ok ? "ok preview checks passed\n" : "!  preview checks failed\n");
  process.exit(ok ? 0 : 1);
}

main().catch((error) => {
  process.stderr.write(`!  ${error.stack ?? error}\n`);
  process.exit(1);
});
