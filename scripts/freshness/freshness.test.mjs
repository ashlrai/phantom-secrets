import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { GENERATORS, renderMarkedContent } from "./blocks.mjs";
import { githubAnchor, loadSources } from "./sources.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const syncScript = join(repoRoot, "scripts", "freshness", "sync.mjs");
const checkScript = join(repoRoot, "scripts", "freshness", "check.mjs");
const ctx = loadSources(repoRoot);

function run(script, args) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

function render(name) {
  const generator = GENERATORS.get(name);
  assert.ok(generator, `generator '${name}' must be registered`);
  return { type: generator.type, output: generator.render(ctx, "test.md") };
}

test("version-badge blocks pin the release tag and changelog anchor", () => {
  const { type, output } = render("readme-release-badges");
  assert.equal(type, "version-badge");
  assert.match(
    output,
    new RegExp(`verified_GitHub_release-${ctx.tag}-`),
  );
  assert.match(output, new RegExp(`releases/tag/${ctx.tag}`));
  assert.match(output, new RegExp(`CHANGELOG.md#${ctx.release.anchor}`));
});

test("install-snippet blocks pin exact package versions", () => {
  const cli = render("npm-cli-install");
  assert.equal(cli.type, "install-snippet");
  assert.match(
    cli.output,
    new RegExp(
      `npm install --global phantom-secrets@${ctx.version.replaceAll(".", "\\.")}`,
    ),
  );
  assert.match(cli.output, /phantom --version/);

  const mcp = render("npm-mcp-install");
  assert.equal(mcp.type, "install-snippet");
  assert.match(
    mcp.output,
    new RegExp(`npm view phantom-secrets-mcp@${ctx.version.replaceAll(".", "\\.")}`),
  );
  assert.match(mcp.output, /phantom-mcp --version/);
});

test("version-table blocks regenerate the release asset matrix", () => {
  const { type, output } = render("readme-release-asset-table");
  assert.equal(type, "version-table");
  const rows = output.split("\n").filter((line) => line.startsWith("| "));
  assert.equal(rows.length, 7);
  assert.match(output, new RegExp(`\\| Platform \\| \`${ctx.tag}\` archive`));
  for (const artifact of [
    "phantom-aarch64-apple-darwin.tar.gz",
    "phantom-x86_64-apple-darwin.tar.gz",
    "phantom-x86_64-unknown-linux-gnu.tar.gz",
    "phantom-aarch64-unknown-linux-gnu.tar.gz",
    "phantom-x86_64-pc-windows-msvc.zip",
    "phantom-aarch64-pc-windows-msvc.zip",
  ]) {
    assert.match(
      output,
      new RegExp(`releases/download/${ctx.tag}/${artifact}`),
    );
    assert.match(output, new RegExp(`${artifact}\\.sha256`));
  }
});

test("version-pin blocks pin the release tag in prose and link refs", () => {
  const compare = render("changelog-unreleased-compare");
  assert.equal(compare.type, "version-pin");
  assert.equal(
    compare.output,
    `[Unreleased]: https://github.com/ashlrai/phantom-secrets/compare/${ctx.tag}...HEAD`,
  );

  const wrapper = render("npm-cli-wrapper-version");
  assert.equal(wrapper.type, "version-pin");
  assert.match(wrapper.output, new RegExp(`version \`${ctx.version}\``));

  const verify = render("docs-verify-version-output");
  assert.match(verify.output, new RegExp(`# phantom ${ctx.version}\n`));
  assert.match(verify.output, new RegExp(`# phantom-mcp ${ctx.version}`));
});

test("the changelog anchor matches the GitHub heading slug", () => {
  assert.equal(githubAnchor("[0.7.9] - 2026-09-06"), "079---2026-09-06");
  assert.equal(githubAnchor("[1.20.3] - 2030-11-04"), "1203---2030-11-04");
  assert.equal(ctx.release.anchor, githubAnchor(`[${ctx.version}] - ${ctx.release.date}`));
});

test("structural marker errors fail closed", () => {
  assert.throws(
    () =>
      renderMarkedContent(
        "<!-- fresh:begin readme-release-badges -->\nstale\n",
        ctx,
        "broken.md",
      ),
    /has no fresh:end/,
  );
  assert.throws(
    () =>
      renderMarkedContent(
        "<!-- fresh:end -->\n",
        ctx,
        "broken.md",
      ),
    /fresh:end without fresh:begin/,
  );
  assert.throws(
    () =>
      renderMarkedContent(
        "<!-- fresh:begin no-such-block -->\nx\n<!-- fresh:end -->\n",
        ctx,
        "broken.md",
      ),
    /unknown fresh block 'no-such-block'/,
  );
  assert.throws(
    () =>
      renderMarkedContent(
        "<!-- fresh:begin readme-release-badges -->\n<!-- fresh:begin readme-release-badges -->\n<!-- fresh:end -->\n",
        ctx,
        "broken.md",
      ),
    /nested fresh:begin/,
  );
});

test("check exits nonzero on a seeded drift fixture and zero after sync", (t) => {
  const fixture = mkdtempSync(join(tmpdir(), "freshness-"));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));

  writeFileSync(
    join(fixture, "Cargo.toml"),
    '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "9.8.7"\n',
  );
  writeFileSync(
    join(fixture, "CHANGELOG.md"),
    "# Changelog\n\n## [Unreleased]\n\n## [9.8.7] - 2030-01-02\n\n- Notes.\n",
  );
  mkdirSync(join(fixture, "npm"), { recursive: true });
  writeFileSync(
    join(fixture, "npm/package.json"),
    JSON.stringify({ name: "phantom-secrets", version: "9.8.7" }),
  );
  mkdirSync(join(fixture, "npm-mcp"), { recursive: true });
  writeFileSync(
    join(fixture, "npm-mcp/package.json"),
    JSON.stringify({ name: "phantom-secrets-mcp", version: "9.8.7" }),
  );
  mkdirSync(join(fixture, "docs"), { recursive: true });
  const docPath = join(fixture, "docs", "guide.md");
  writeFileSync(
    docPath,
    [
      "# Guide",
      "",
      "<!-- fresh:begin docs-verify-version-output -->",
      "```bash",
      "phantom --version",
      "phantom-mcp --version",
      "# phantom 0.0.0",
      "# phantom-mcp 0.0.0",
      "```",
      "<!-- fresh:end -->",
      "",
      "Sentinel line outside the block.",
      "",
    ].join("\n"),
  );

  const drifted = run(checkScript, ["--root", fixture]);
  assert.notEqual(drifted.status, 0, drifted.stdout + drifted.stderr);
  assert.match(drifted.stderr, /docs\/guide\.md.*'docs-verify-version-output' is stale/);

  const synced = run(syncScript, ["--root", fixture]);
  assert.equal(synced.status, 0, synced.stderr);
  const rewritten = readFileSync(docPath, "utf8");
  assert.match(rewritten, /# phantom 9\.8\.7\n# phantom-mcp 9\.8\.7/);
  assert.match(rewritten, /Sentinel line outside the block\./);

  const fresh = run(checkScript, ["--root", fixture]);
  assert.equal(fresh.status, 0, fresh.stderr);
});

test("committed blocks are in sync with the workspace version", () => {
  const result = run(checkScript, []);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /freshness check passed/);
});
