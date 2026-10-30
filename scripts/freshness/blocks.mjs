#!/usr/bin/env node

// Marked-block engine for the freshness generator. A block is
//
//   <!-- fresh:begin name -->
//   ...generated content...
//   <!-- fresh:end -->
//
// with both markers on their own line. `sync.mjs` rewrites the content
// between the markers; `check.mjs` reports blocks whose content differs
// from what the generators produce. Everything outside markers is left
// byte-for-byte untouched.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const BEGIN_MARKER =
  /^[ \t]*<!--\s*fresh:begin\s+([A-Za-z0-9][A-Za-z0-9_-]*)\s*-->[ \t]*$/;
export const END_MARKER = /^[ \t]*<!--\s*fresh:end\s*-->[ \t]*$/;

const RELEASES =
  "https://github.com/ashlrai/phantom-secrets/releases";

function assetRow(tag, label, artifact) {
  const url = `${RELEASES}/download/${tag}/${artifact}`;
  return `| ${label} | [\`${artifact}\`](${url}) | [\`sha256\`](${url}.sha256) |`;
}

function assetTable(tag, appleSiliconLabel) {
  const rows = [
    [appleSiliconLabel, "phantom-aarch64-apple-darwin.tar.gz"],
    ["macOS Intel", "phantom-x86_64-apple-darwin.tar.gz"],
    ["Linux x86_64", "phantom-x86_64-unknown-linux-gnu.tar.gz"],
    ["Linux ARM64", "phantom-aarch64-unknown-linux-gnu.tar.gz"],
    ["Windows x64", "phantom-x86_64-pc-windows-msvc.zip"],
    ["Windows ARM64", "phantom-aarch64-pc-windows-msvc.zip"],
  ];
  return [
    `| Platform | \`${tag}\` archive | Published checksum |`,
    "|---|---|---|",
    ...rows.map(([label, artifact]) => assetRow(tag, label, artifact)),
  ].join("\n");
}

function npmInstallSnippet(packageName, binaryName, version) {
  return [
    "```bash",
    `npm view ${packageName}@${version} version dist.integrity dist.tarball --registry=https://registry.npmjs.org/`,
    `npm install --global ${packageName}@${version} --registry=https://registry.npmjs.org/`,
    `${binaryName} --version`,
    "```",
  ].join("\n");
}

// One entry per block name. `type` is the freshness block category used
// by the test suite: version badges, install snippets, version tables and
// example version pins.
export const GENERATORS = new Map([
  [
    "readme-release-badges",
    {
      type: "version-badge",
      render: (ctx) =>
        [
          `[![Verified GitHub release](https://img.shields.io/badge/verified_GitHub_release-${ctx.tag}-2f81f7?style=for-the-badge&labelColor=0b0b14)](${RELEASES}/tag/${ctx.tag})`,
          `[![Source version](https://img.shields.io/badge/source_version-${ctx.tag}-f5a623?style=for-the-badge&labelColor=0b0b14)](CHANGELOG.md#${ctx.release.anchor})`,
        ].join("\n"),
    },
  ],
  [
    "readme-release-asset-table",
    {
      type: "version-table",
      render: (ctx) => assetTable(ctx.tag, "macOS Apple Silicon"),
    },
  ],
  [
    "docs-release-asset-table",
    {
      type: "version-table",
      render: (ctx) => assetTable(ctx.tag, "macOS Apple silicon"),
    },
  ],
  [
    "npm-cli-install",
    {
      type: "install-snippet",
      render: (ctx) =>
        npmInstallSnippet(ctx.npmCli.name, "phantom", ctx.version),
    },
  ],
  [
    "npm-mcp-install",
    {
      type: "install-snippet",
      render: (ctx) =>
        npmInstallSnippet(ctx.npmMcp.name, "phantom-mcp", ctx.version),
    },
  ],
  [
    "npm-cli-wrapper-version",
    {
      type: "version-pin",
      render: (ctx) =>
        [
          `This wrapper is version \`${ctx.version}\`. Its manifest and this README do not prove that`,
          "the npm package or matching GitHub release has been published. Verify the exact",
          "npm version before installing it:",
        ].join("\n"),
    },
  ],
  [
    "npm-mcp-wrapper-version",
    {
      type: "version-pin",
      render: (ctx) =>
        [
          `This wrapper is version \`${ctx.version}\`. Its manifest and this README do not prove npm,`,
          "GitHub, or MCP Registry publication. Verify the exact npm version before",
          "installing it:",
        ].join("\n"),
    },
  ],
  [
    "changelog-unreleased-compare",
    {
      type: "version-pin",
      render: (ctx) =>
        `[Unreleased]: https://github.com/ashlrai/phantom-secrets/compare/${ctx.tag}...HEAD`,
    },
  ],
  [
    "docs-verify-version-output",
    {
      type: "version-pin",
      render: (ctx) =>
        [
          "```bash",
          "phantom --version",
          "phantom-mcp --version",
          `# phantom ${ctx.version}`,
          `# phantom-mcp ${ctx.version}`,
          "```",
        ].join("\n"),
    },
  ],
  [
    "examples-gate-verified-release",
    {
      type: "version-pin",
      render: (ctx) =>
        [
          `This recipe passes against both the ${ctx.tag} release and the workspace build.`,
          "The install step in the workflow was also run as written on Linux x86_64",
          `(\`gh release download\`, \`sha256sum -c\`, \`phantom --version\` → \`phantom ${ctx.version}\`).`,
        ].join("\n"),
    },
  ],
]);

// Scan order: explicit root-level files, then every Markdown file under
// docs/ and examples/ (hidden directories and node_modules are skipped).
const EXPLICIT_FILES = [
  "README.md",
  "CHANGELOG.md",
  "npm/README.md",
  "npm-mcp/README.md",
];
const SCANNED_DIRS = ["docs", "examples"];

function walk(root, relDir, out) {
  const abs = join(root, relDir);
  let entries;
  try {
    entries = readdirSync(abs, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const rel = `${relDir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
      walk(root, rel, out);
    } else if (entry.name.endsWith(".md")) {
      out.push(rel);
    }
  }
}

export function collectTargets(root) {
  const targets = [];
  for (const rel of EXPLICIT_FILES) {
    if (existsSync(join(root, rel))) targets.push(rel);
  }
  for (const dir of SCANNED_DIRS) {
    walk(root, dir, targets);
  }
  return targets.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

// Replace the body of every marked block in `content` with freshly
// rendered output. Returns the rewritten content plus one record per
// block ({name, type, line, changed}). Throws on structural problems:
// unknown names, missing or nested markers, stray fresh:end lines.
export function renderMarkedContent(content, ctx, relPath) {
  const lines = content.split("\n");
  const out = [];
  const blocks = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const begin = line.match(BEGIN_MARKER);
    if (!begin) {
      if (END_MARKER.test(line)) {
        throw new Error(`${relPath}:${i + 1}: fresh:end without fresh:begin`);
      }
      out.push(line);
      i += 1;
      continue;
    }

    const name = begin[1];
    const generator = GENERATORS.get(name);
    if (!generator) {
      throw new Error(
        `${relPath}:${i + 1}: unknown fresh block '${name}' ` +
          `(known: ${[...GENERATORS.keys()].join(", ")})`,
      );
    }

    let end = -1;
    for (let j = i + 1; j < lines.length; j += 1) {
      if (BEGIN_MARKER.test(lines[j])) {
        throw new Error(
          `${relPath}:${j + 1}: nested fresh:begin inside block '${name}'`,
        );
      }
      if (END_MARKER.test(lines[j])) {
        end = j;
        break;
      }
    }
    if (end === -1) {
      throw new Error(
        `${relPath}:${i + 1}: fresh block '${name}' has no fresh:end`,
      );
    }

    const rendered = generator.render(ctx, relPath);
    if (typeof rendered !== "string" || rendered === "") {
      throw new Error(`fresh block '${name}' rendered empty content`);
    }
    if (BEGIN_MARKER.test(rendered) || END_MARKER.test(rendered)) {
      throw new Error(`fresh block '${name}' generated a marker line`);
    }

    const previous = lines.slice(i + 1, end).join("\n");
    out.push(line, ...rendered.split("\n"), lines[end]);
    blocks.push({
      name,
      type: generator.type,
      line: i + 1,
      changed: previous !== rendered,
    });
    i = end + 1;
  }
  return { content: out.join("\n"), blocks };
}

export function planFile(root, rel, ctx) {
  const before = readFileSync(join(root, rel), "utf8");
  const { content: after, blocks } = renderMarkedContent(before, ctx, rel);
  return { rel, before, after, blocks, changed: after !== before };
}
