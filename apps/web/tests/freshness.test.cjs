// Freshness contract for the generated `fresh:` blocks. These tests prove
// the check fails when a page drifts from the repository sources (version,
// release evidence, MCP catalog, CLI surface, setup clients) and that the
// marker engine fails closed on malformed blocks.
//
// Fixture roots are assembled under a temporary directory: the real
// repository's sources are copied in, then individual inputs are mutated so
// each scenario exercises one drift axis without touching the worktree.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { execFileSync } = require("node:child_process");
const { pathToFileURL } = require("node:url");

const webDir = path.resolve(__dirname, "..");
const repoDir = path.resolve(webDir, "../..");
const scriptsDir = path.join(webDir, "scripts/freshness");

const blocksModule = import(pathToFileURL(path.join(scriptsDir, "blocks.mjs")));
const sourcesModule = import(pathToFileURL(path.join(scriptsDir, "sources.mjs")));
const checkModule = import(pathToFileURL(path.join(scriptsDir, "check.mjs")));

// Files the sources loader reads, relative to a fixture root. Everything
// else the generator touches is created by the fixture builder.
const SOURCE_FILES = [
  "Cargo.toml",
  "CHANGELOG.md",
  "npm/package.json",
  "npm-mcp/package.json",
  "apps/web/package.json",
  "apps/web/docs-catalog.json",
  "mcp-registry/server.json",
  "crates/phantom-cli/src/main.rs",
  "crates/phantom-cli/src/commands/setup.rs",
  "apps/web/src/lib/public-release.ts",
  // SITEMAP_PAGES sources: the generators ask git for each file's lastmod.
  "apps/web/src/app/page.tsx",
  "apps/web/src/app/secrets/page.tsx",
  "apps/web/src/app/docs/page.tsx",
  "apps/web/src/app/docs/manifest.json/route.ts",
  "apps/web/src/app/pricing/page.tsx",
  "apps/web/src/app/enterprise/page.tsx",
  "apps/web/src/app/government/page.tsx",
  "apps/web/src/app/security/page.tsx",
  "apps/web/public/workbench/llms.txt",
  "apps/web/public/workbench/llms-full.txt",
];

function git(root, args) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

// An empty target body: every block the file is expected to carry, rendered
// as begin/end marker pairs with nothing between them.
async function markerShell(file) {
  const { TARGETS } = await blocksModule;
  const comment = /\.tsx?$/.test(file) ? "//" : "<!--";
  const close = comment === "<!--" ? " -->" : "";
  const body = TARGETS.get(file)
    .map(
      (name) =>
        `${comment} fresh:begin ${name}${close}\n${comment} fresh:end${close}`,
    )
    .join("\n");
  return `${body}\n`;
}

// Build a fixture root containing the repository's real sources plus empty
// target shells, then apply `mutate` to individual files before they are
// committed. Returns the root.
async function fixtureRoot(mutate) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "freshness-fixture-"));
  for (const rel of SOURCE_FILES) {
    const target = path.join(root, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(repoDir, rel), target);
  }
  for (const entry of JSON.parse(
    fs.readFileSync(path.join(repoDir, "apps/web/docs-catalog.json"), "utf8"),
  )) {
    const target = path.join(root, "docs", entry.file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(repoDir, "docs", entry.file), target);
  }

  const { TARGETS } = await blocksModule;
  for (const [file] of TARGETS) {
    const target = path.join(root, file);
    if (fs.existsSync(target)) continue;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, await markerShell(file));
  }

  mutate?.(root);

  // The sitemap and evidence loaders read committed dates and tag objects;
  // a throwaway git history inside the fixture supplies both without
  // touching the real worktree.
  git(root, ["init", "-q"]);
  git(root, ["config", "user.email", "freshness-test@example.invalid"]);
  git(root, ["config", "user.name", "Freshness Test"]);
  git(root, ["add", "."]);
  git(root, ["commit", "-qm", "fixture", "--date=2026-10-01T00:00:00Z"]);
  git(root, ["tag", "-a", "v0.7.9", "-m", "fixture tag"]);

  // Point the release evidence at the fixture tag plumbing so the loader's
  // git-resolved branch still verifies in this isolated root.
  const releasePath = path.join(root, "apps/web/src/lib/public-release.ts");
  const tagObject = git(root, ["rev-parse", "v0.7.9"]);
  const tagCommit = git(root, ["rev-parse", "v0.7.9^{}"]);
  const rewritten = fs
    .readFileSync(releasePath, "utf8")
    .replace(
      /PUBLIC_RELEASE_SOURCE_COMMIT\s*=\s*"[a-f0-9]{40}"/,
      `PUBLIC_RELEASE_SOURCE_COMMIT = "${tagCommit}"`,
    )
    .replace(
      /PUBLIC_RELEASE_TAG_OBJECT\s*=\s*"[a-f0-9]{40}"/,
      `PUBLIC_RELEASE_TAG_OBJECT = "${tagObject}"`,
    );
  fs.writeFileSync(releasePath, rewritten);
  return root;
}

test("check flags a hand-edited stale version in a target page", async () => {
  const root = await fixtureRoot();
  const { checkAll } = await checkModule;
  const releasePath = path.join(root, "apps/web/src/lib/public-release.ts");
  const stale = fs
    .readFileSync(releasePath, "utf8")
    .replace(
      'const PUBLIC_RELEASE_VERSION = "',
      'const PUBLIC_RELEASE_VERSION = "0.0.0"; const _ = "',
    );
  fs.writeFileSync(releasePath, stale);
  const drift = checkAll(root).filter(
    (entry) => entry.block === "public-release-version",
  );
  assert.equal(drift.length, 1);
  assert.match(drift[0].expected, /PUBLIC_RELEASE_VERSION = "0\.7\.9"/);
});

test("check flags a stale setup-client list that misses a real client", async () => {
  const root = await fixtureRoot();
  const { checkAll } = await checkModule;
  const target = path.join(root, "docs/llms.txt");
  const stale = fs
    .readFileSync(target, "utf8")
    .replace(
      /<!-- fresh:begin docs-llms-mcp-setup -->\n<!-- fresh:end -->/,
      "<!-- fresh:begin docs-llms-mcp-setup -->\n- Claude Code: `phantom setup --client claude` (writes .mcp.json)\n- Cursor: `phantom setup --client cursor` (writes ~/.cursor/mcp.json)\n<!-- fresh:end -->",
    );
  fs.writeFileSync(target, stale);
  const drift = checkAll(root).filter(
    (entry) => entry.block === "docs-llms-mcp-setup",
  );
  assert.equal(drift.length, 1);
  assert.match(drift[0].expected, /--client gemini/);
});

test("check flags a tool catalog that drops a shipped MCP tool", async () => {
  const root = await fixtureRoot();
  const { checkAll } = await checkModule;
  const target = path.join(root, "apps/web/public/llms.txt");
  const stale = fs
    .readFileSync(target, "utf8")
    .replace(
      /<!-- fresh:begin llms-tool-catalog -->\n<!-- fresh:end -->/,
      "<!-- fresh:begin llms-tool-catalog -->\nSecrets and dotenv: `phantom_init`\n<!-- fresh:end -->",
    );
  fs.writeFileSync(target, stale);
  const drift = checkAll(root).filter(
    (entry) =>
      entry.file === "apps/web/public/llms.txt" &&
      entry.block === "llms-tool-catalog",
  );
  assert.equal(drift.length, 1);
  assert.match(drift[0].expected, /phantom_rotate_provider/);
});

test("loadSources fails closed when the version files disagree", async () => {
  const root = await fixtureRoot((dir) => {
    const manifest = path.join(dir, "npm/package.json");
    const parsed = JSON.parse(fs.readFileSync(manifest, "utf8"));
    parsed.version = "0.0.1";
    fs.writeFileSync(manifest, JSON.stringify(parsed, null, 2));
  });
  const { loadSources } = await sourcesModule;
  assert.throws(() => loadSources(root), /sources disagree/);
});

test("loadSources fails closed when release evidence is unbound", async () => {
  const root = await fixtureRoot((dir) => {
    const releasePath = path.join(dir, "apps/web/src/lib/public-release.ts");
    const source = fs
      .readFileSync(releasePath, "utf8")
      .replace(
        /PUBLIC_RELEASE_EVIDENCE_STATE\s*=\s*"bound"/,
        'PUBLIC_RELEASE_EVIDENCE_STATE = "pending"',
      );
    fs.writeFileSync(releasePath, source);
  });
  const { loadSources } = await sourcesModule;
  assert.throws(() => loadSources(root), /evidence is pending/);
});

test("generation fails closed when a setup client lacks site presentation", async () => {
  const root = await fixtureRoot((dir) => {
    const setupPath = path.join(dir, "crates/phantom-cli/src/commands/setup.rs");
    const source = fs
      .readFileSync(setupPath, "utf8")
      .replace(
        /(Gemini,)/,
        "$1\n    /// Test client writes `mcpServers` in ~/.gemini/settings.json\n    #[value(name = \"testclient\")]\n    Testclient,",
      )
      .replace(
        /(Client::Gemini => "Gemini CLI",)/,
        '$1\n            Client::Testclient => "Test Client",',
      );
    fs.writeFileSync(setupPath, source);
  });
  const { loadSources } = await sourcesModule;
  const { applyBlocks } = await blocksModule;
  const ctx = loadSources(root);
  assert.throws(
    () =>
      applyBlocks(
        "// fresh:begin install-clients\n// fresh:end\n",
        "apps/web/src/components/landing/Install.tsx",
        ctx,
      ),
    /no CLIENT_PRESENTATION row/,
  );
});

test("generation fails closed when the MCP catalog gains an unmapped tool", async () => {
  const root = await fixtureRoot((dir) => {
    const registryPath = path.join(dir, "mcp-registry/server.json");
    const registry = JSON.parse(fs.readFileSync(registryPath, "utf8"));
    registry.tools.push({
      name: "phantom_unmapped_probe",
      description: "Probe tool added by the fixture.",
      inputSchema: { type: "object", properties: {} },
    });
    fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2));
  });
  const { loadSources } = await sourcesModule;
  const { applyBlocks } = await blocksModule;
  const ctx = loadSources(root);
  assert.throws(
    () =>
      applyBlocks(
        "<!-- fresh:begin llms-tool-catalog -->\n<!-- fresh:end -->\n",
        "apps/web/public/llms.txt",
        ctx,
      ),
    /no TOOL_CATEGORIES group/,
  );
});

test("marker engine fails closed on stray, nested, unknown, and unterminated blocks", async () => {
  const root = await fixtureRoot();
  const { loadSources } = await sourcesModule;
  const { applyBlocks } = await blocksModule;
  const ctx = loadSources(root);
  const file = "apps/web/public/llms.txt";

  assert.throws(
    () =>
      applyBlocks(
        "<!-- fresh:begin nope -->\n<!-- fresh:end -->\n",
        file,
        ctx,
      ),
    /unknown freshness block/,
  );
  assert.throws(
    () =>
      applyBlocks(
        "<!-- fresh:begin release-receipt -->\nno end marker\n",
        file,
        ctx,
      ),
    /no fresh:end/,
  );
  assert.throws(
    () =>
      applyBlocks(
        "<!-- fresh:begin release-receipt -->\n<!-- fresh:begin cli-surface -->\n<!-- fresh:end -->\n",
        file,
        ctx,
      ),
    /nested freshness block/,
  );
  assert.throws(() => applyBlocks("<!-- fresh:end -->\n", file, ctx), /unmatched freshness marker/);
  assert.throws(
    () =>
      applyBlocks(
        "# fresh:begin release-receipt\n# fresh:end\n",
        file,
        ctx,
      ),
    /unmatched freshness marker/,
  );
});

test("generated content preserves surrounding bytes and ends files cleanly", async () => {
  const { applyBlocks } = await blocksModule;
  const { loadSources } = await sourcesModule;
  const ctx = loadSources(repoDir);
  const prologue = "header line\n\n";
  const epilogue = "\nfooter line\n";
  const { content } = applyBlocks(
    `${prologue}${await markerShell("apps/web/public/llms.txt")}${epilogue}`,
    "apps/web/public/llms.txt",
    ctx,
  );
  assert.ok(content.startsWith(prologue));
  assert.ok(content.endsWith(epilogue));
  assert.match(
    content,
    /releases\/tag\/v0\.7\.9[\s\S]*7a51ce512ec4aee12cc29ff859036af63fbe93db/,
  );
});

test("real worktree has no freshness drift", async () => {
  const { checkAll } = await checkModule;
  const stale = checkAll(repoDir);
  assert.deepEqual(
    stale.map((entry) => `${entry.file}:${entry.block}`),
    [],
  );
});

test("generated blocks contain no release evidence sentinels or em dashes", async () => {
  const root = await fixtureRoot();
  const { GENERATORS, TARGETS } = await blocksModule;
  const { loadSources } = await sourcesModule;
  const ctx = loadSources(root);
  for (const [file, names] of TARGETS) {
    for (const name of names) {
      const rendered = GENERATORS.get(name).render(ctx, file);
      assert.doesNotMatch(rendered, /PENDING|pending-exact-receipts/, name);
      assert.doesNotMatch(rendered, /[\u2013\u2014]/, name);
    }
  }
});

test("generated MCP catalogs cover every staged tool exactly once", async () => {
  const root = await fixtureRoot();
  const { applyBlocks } = await blocksModule;
  const { loadSources } = await sourcesModule;
  const ctx = loadSources(root);
  const schemaNames = new Set(ctx.tools.map((tool) => tool.name));
  // Descriptions legitimately mention `phantom_`-shaped field names (for
  // example `phantom_token`), so names are matched only in the entry
  // position each catalog format reserves for them.
  for (const [file, pattern] of [
    ["apps/web/public/llms.txt", /`phantom_[a-z0-9_]+`/g],
    ["apps/web/public/llms-full.txt", /^phantom_[a-z0-9_]+\b/gm],
    ["docs/llms.txt", /`phantom_[a-z0-9_]+`/g],
    ["docs/llms-full.txt", /^- `phantom_[a-z0-9_]+`:/gm],
  ]) {
    const { content } = applyBlocks(await markerShell(file), file, ctx);
    const names = new Set(
      [...content.matchAll(pattern)].map((match) =>
        match[0].replace(/[-:`]/g, "").trim(),
      ),
    );
    assert.deepEqual([...names].sort(), [...schemaNames].sort(), file);
  }
});

test("setup client surfaces cover every CLI --client value", async () => {
  const root = await fixtureRoot();
  const { applyBlocks } = await blocksModule;
  const { loadSources } = await sourcesModule;
  const ctx = loadSources(root);
  const { content } = applyBlocks(
    "// fresh:begin install-clients\n// fresh:end\n",
    "apps/web/src/components/landing/Install.tsx",
    ctx,
  );
  for (const client of ctx.clients) {
    assert.match(content, new RegExp(`id: "${client.id}"`));
    assert.match(content, new RegExp(`phantom setup --client ${client.id}`));
  }
});
