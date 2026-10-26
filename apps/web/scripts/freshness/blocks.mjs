#!/usr/bin/env node

// Marked-block engine for the site freshness generator. A block is
//
//   <!-- fresh:begin name -->      (markdown, txt, xml, html)
//   // fresh:begin name            (ts, tsx, js, mjs, cjs)
//   # fresh:begin name             (toml, yaml, shell)
//   ...generated content...
//   <!-- fresh:end -->             (matching style)
//
// with both markers on their own line. `sync.mjs` rewrites the content
// between the markers; `check.mjs` reports blocks whose content differs
// from what the generators produce. Everything outside markers is left
// byte-for-byte untouched.
//
// The marker keywords match scripts/freshness/ (RQ-FRESH-GEN-PS) so the
// two generators can share blocks once that stack merges; this one adds
// `//` and `#` comment styles for code and config files.

import { extname } from "node:path";

const BLOCK_NAME = "[A-Za-z0-9][A-Za-z0-9_-]*";

const MARKER_STYLES = {
  html: {
    begin: new RegExp(`^[ \\t]*<!--\\s*fresh:begin\\s+(${BLOCK_NAME})\\s*-->[ \\t]*$`),
    end: /^[ \t]*<!--\s*fresh:end\s*-->[ \t]*$/,
  },
  line: {
    begin: new RegExp(`^[ \\t]*\\/\\/\\s*fresh:begin\\s+(${BLOCK_NAME})[ \\t]*$`),
    end: /^[ \t]*\/\/\s*fresh:end[ \t]*$/,
  },
  hash: {
    begin: new RegExp(`^[ \\t]*#\\s*fresh:begin\\s+(${BLOCK_NAME})[ \\t]*$`),
    end: /^[ \t]*#\s*fresh:end[ \t]*$/,
  },
};

const STYLE_BY_EXTENSION = {
  ".md": "html",
  ".txt": "html",
  ".xml": "html",
  ".html": "html",
  ".ts": "line",
  ".tsx": "line",
  ".js": "line",
  ".mjs": "line",
  ".cjs": "line",
  ".toml": "hash",
  ".yaml": "hash",
  ".yml": "hash",
  ".sh": "hash",
  ".ps1": "hash",
};

const ANY_MARKER = /fresh:(?:begin|end)\b/;

const RELEASES = "https://github.com/ashlrai/phantom-secrets/releases";

// Verified receipt counts from the bound release evidence. These describe
// the reviewed release, not anything derivable from source; the claims
// suite pins the same numbers, so updating them is part of re-binding the
// receipt at each release.
const RECEIPT_ASSET_COUNT = 19;
const RECEIPT_NATIVE_ROWS = "six";

const RELEASE_ARTIFACTS = [
  ["macOS Apple Silicon", "phantom-aarch64-apple-darwin.tar.gz"],
  ["macOS Intel", "phantom-x86_64-apple-darwin.tar.gz"],
  ["Linux x86_64", "phantom-x86_64-unknown-linux-gnu.tar.gz"],
  ["Linux ARM64", "phantom-aarch64-unknown-linux-gnu.tar.gz"],
  ["Windows x64", "phantom-x86_64-pc-windows-msvc.zip"],
  ["Windows ARM64", "phantom-aarch64-pc-windows-msvc.zip"],
];

// Editorial per-client presentation the CLI source cannot supply: the logo
// component, the supervised launch example, and whether the config is
// project or user scoped. A client enum entry with no presentation row (or
// a stale row for a removed client) fails generation closed so a human
// picks the presentation deliberately.
const CLIENT_PRESENTATION = {
  claude: {
    logo: "ClaudeClientLogo",
    launch: "phantom exec -- claude",
    scope: "project",
    tableNote: " (project; also hardens `.claude/settings.local.json`)",
    listNote: "; project-scoped; also hardens `.claude/settings.local.json`",
  },
  cursor: {
    logo: "CursorClientLogo",
    launch: "phantom exec -- cursor .",
    scope: "user",
  },
  windsurf: {
    logo: "WindsurfClientLogo",
    launch: "phantom exec -- windsurf .",
    scope: "user",
  },
  codex: {
    logo: "CodexClientLogo",
    launch: 'phantom exec -- codex "<your task>"',
    scope: "user",
  },
  gemini: {
    logo: "GeminiClientLogo",
    launch: "phantom exec -- gemini",
    scope: "user",
  },
};

// Canonical catalog grouping. Every tool in mcp-registry/server.json must
// land in exactly one group; an unmapped tool fails generation so a human
// reviews where the new tool belongs instead of silently dropping it.
const TOOL_CATEGORIES = [
  [
    "Secrets and dotenv",
    [
      "phantom_init",
      "phantom_list_secrets",
      "phantom_list_with_expiry",
      "phantom_status",
      "phantom_add_secret_interactive",
      "phantom_add_secret",
      "phantom_remove_secret",
      "phantom_rotate",
      "phantom_copy_secret",
    ],
  ],
  [
    "Diagnostics",
    [
      "phantom_doctor",
      "phantom_why",
      "phantom_check",
      "phantom_env",
      "phantom_capability",
    ],
  ],
  [
    "Sync and script wrapping",
    ["phantom_sync", "phantom_wrap", "phantom_unwrap"],
  ],
  [
    "Cloud backup (requires a separately commissioned hosted service)",
    ["phantom_cloud_push", "phantom_cloud_pull", "phantom_cloud_status"],
  ],
  [
    "Teams (requires a separately commissioned hosted service)",
    [
      "phantom_team_list",
      "phantom_team_members",
      "phantom_team_key_publish",
      "phantom_team_create",
      "phantom_team_invite",
      "phantom_team_vault_push",
      "phantom_team_vault_pull",
    ],
  ],
  [
    "Workspace and guided actions",
    ["phantom_setup_workspace", "phantom_do"],
  ],
  [
    "Audit, compliance, and leak incidents",
    [
      "phantom_audit_alerts",
      "phantom_audit_analytics",
      "phantom_audit_anomalies",
      "phantom_audit_anomalies_realtime",
      "phantom_audit_export_report",
      "phantom_audit_hotspot_alerts",
      "phantom_audit_incidents",
      "phantom_audit_recent",
      "phantom_audit_stats",
      "phantom_compliance_status",
      "phantom_leak_incidents_realtime",
    ],
  ],
  [
    "Validation, expiry, and rotation",
    [
      "phantom_validate_all",
      "phantom_validate_secret",
      "phantom_validation_history",
      "phantom_validation_schedule",
      "phantom_expiry_enforce",
      "phantom_apply_expiry_policy",
      "phantom_secrets_expiry_check",
      "phantom_secret_rotation_due",
      "phantom_rotation_schedule_next",
      "phantom_rotate_with_expiry",
      "phantom_secrets_auto_rotate",
      "phantom_rotate_with_candidate",
      "phantom_rotate_promote",
      "phantom_rotate_provider",
    ],
  ],
];

// Route -> source file whose committed lastmod dates it.
const SITEMAP_PAGES = [
  ["/", "src/app/page.tsx"],
  ["/secrets", "src/app/secrets/page.tsx"],
  ["/docs", "src/app/docs/page.tsx"],
  ["/docs/manifest.json", "src/app/docs/manifest.json/route.ts"],
  ["/workbench/llms.txt", "public/workbench/llms.txt"],
  ["/workbench/llms-full.txt", "public/workbench/llms-full.txt"],
  ["/pricing", "src/app/pricing/page.tsx"],
  ["/enterprise", "src/app/enterprise/page.tsx"],
  ["/government", "src/app/government/page.tsx"],
  ["/security", "src/app/security/page.tsx"],
  ["/llms.txt", "public/llms.txt"],
  ["/llms-full.txt", "public/llms-full.txt"],
];

// When the sitemap source is itself a freshness target, the route's lastmod
// follows the release date instead: the file's content is regenerated, so a
// git-derived date would go stale the moment a freshness sync is committed.
function pageModified(ctx, rel) {
  const source = `apps/web/${rel}`;
  return TARGETS.has(source) ? ctx.release.date : ctx.lastmod(source);
}

function clientsWithPresentation(ctx) {
  const known = new Set(Object.keys(CLIENT_PRESENTATION));
  return ctx.clients.map((client) => {
    const presentation = CLIENT_PRESENTATION[client.id];
    if (!presentation) {
      throw new Error(
        `setup --client ${client.id} has no CLIENT_PRESENTATION row in scripts/freshness/blocks.mjs`,
      );
    }
    known.delete(client.id);
    return { ...client, presentation };
  }).concat(
    [...known].map((id) => {
      throw new Error(
        `CLIENT_PRESENTATION row ${id} is not a setup --client value in setup.rs`,
      );
    }),
  );
}

function categorizedTools(ctx) {
  const categoryOf = new Map();
  for (const [, tools] of TOOL_CATEGORIES) {
    for (const name of tools) {
      if (categoryOf.has(name)) {
        throw new Error(`tool ${name} appears in two freshness categories`);
      }
      categoryOf.set(name, true);
    }
  }
  for (const tool of ctx.tools) {
    if (!categoryOf.has(tool.name)) {
      throw new Error(
        `MCP tool ${tool.name} has no TOOL_CATEGORIES group in scripts/freshness/blocks.mjs`,
      );
    }
  }
  const byName = new Map(ctx.tools.map((tool) => [tool.name, tool]));
  return TOOL_CATEGORIES.map(([label, names]) => [
    label,
    names.map((name) => {
      const tool = byName.get(name);
      if (!tool) {
        throw new Error(
          `TOOL_CATEGORIES names ${name}, which is not in mcp-registry/server.json`,
        );
      }
      return tool;
    }),
  ]);
}

// Whole sentences from a schema description: `e.g.`/`i.e.`/`vs.`/`etc.`
// are not sentence boundaries.
function sentences(text) {
  const parts = text.split(/(?<=[.?!]) /);
  const merged = [];
  for (const part of parts) {
    const last = merged[merged.length - 1];
    if (last && /\b(?:e\.g|i\.e|cf|vs|etc)\.$/.test(last)) {
      merged[merged.length - 1] = `${last} ${part}`;
    } else {
      merged.push(part);
    }
  }
  return merged;
}

function toolSummary(tool, budget = 400) {
  const chunks = sentences(tool.description);
  let summary = chunks[0] ?? "";
  for (const chunk of chunks.slice(1)) {
    if (summary.length + 1 + chunk.length > budget) break;
    summary = `${summary} ${chunk}`;
  }
  return summary;
}

function paramsClause(tool) {
  if (tool.params.length === 0) return "";
  const rendered = tool.params.map((name) =>
    tool.optional.has(name) && name !== "confirm" && name !== "approval_token"
      ? `${name} (optional)`
      : name,
  );
  return ` Params: ${rendered.join(", ")}.`;
}

const SCHEMA_TYPE = {
  string: "string",
  boolean: "bool",
  integer: "integer",
  number: "number",
  array: "array",
  object: "object",
};

// `name (type[, default X])` with the gate parameters spelled the way the
// claims suite and the README table write them. On a gated tool `confirm`
// must be `true` for the call to take effect even though the schema leaves
// it optional, so the label describes the gate, not the JSON requirement.
function paramLabel(tool, name) {
  const property = tool.properties[name] ?? {};
  const type = SCHEMA_TYPE[property.type] ?? property.type ?? "value";
  if (name === "confirm") {
    return tool.params.includes("approval_token")
      ? "confirm (bool, must be true)"
      : "confirm (bool, optional)";
  }
  if (name === "approval_token") {
    return "approval_token (string)";
  }
  const extras = [];
  if (property.default !== undefined) {
    extras.push(`default ${JSON.stringify(property.default)}`);
  }
  if (tool.optional.has(name)) extras.push("optional");
  return extras.length === 0
    ? `${name} (${type})`
    : `${name} (${type}, ${extras.join(", ")})`;
}

// Quoted schema prose is normalized for the public surfaces: typographic
// dashes become plain hyphens so generated blocks stay within the
// repository's plain-ASCII punctuation style for new content.
function prose(text) {
  return text.replace(/[\u2013\u2014]/g, "-");
}

function wrapDescription(text, width) {
  const words = prose(text).split(" ");
  const lines = [""];
  for (const word of words) {
    const last = lines[lines.length - 1];
    const next = last === "" ? word : `${last} ${word}`;
    if (next.length > width) lines.push(word);
    else lines[lines.length - 1] = next;
  }
  return lines.map((line) => `  ${line}`).join("\n");
}

// Stanza catalog for the site's llms-full reference. The `(requires ...)`
// annotation on the name line keeps the effect gates visible at a glance and
// pins the exact confirm/approval_token contract the claims tests measure.
function stanzaCatalog(ctx) {
  return categorizedTools(ctx)
    .map(([label, tools]) =>
      [
        `### ${label}`,
        ...tools.map((tool) => {
          const gated = tool.params.includes("approval_token");
          const head = gated
            ? `${tool.name} (requires confirm: true plus approval_token)`
            : tool.name;
          const params =
            tool.params.length === 0
              ? "  Params: none"
              : `  Params: ${tool.params.map((name) => paramLabel(tool, name)).join(", ")}`;
          return [
            head,
            wrapDescription(tool.description, 90),
            params,
          ].join("\n");
        }),
      ].join("\n\n"),
    )
    .join("\n\n");
}

function receiptText(ctx) {
  return [
    `The immutable GitHub \`${ctx.tag}\` release at`,
    `${ctx.releaseTagUrl} resolves to`,
    `\`${ctx.evidence.sourceCommit}\`. Its ${RECEIPT_ASSET_COUNT} assets were published`,
    `after all ${RECEIPT_NATIVE_ROWS} native acceptance rows and release attestations passed in`,
    `${ctx.evidence.workflowUrl}.`,
  ].join("\n");
}

function binariesPin(ctx) {
  return [
    `Install both \`${ctx.tag}\` GitHub release binaries first. Version \`${ctx.version}\` records`,
    "the running `phantom` executable with `mcp serve` when it can resolve that",
    "runtime, otherwise it looks for a local `phantom-mcp`. Setup has no network",
    "package-runner fallback and fails closed when neither local runtime is",
    "executable. Keep both verified binaries installed and inspect the generated",
    "entry.",
  ].join("\n");
}

const HOMEBREW_FENCE = [
  "```",
  "brew tap ashlrai/phantom",
  "brew trust --formula ashlrai/phantom/phantom",
  "brew install ashlrai/phantom/phantom",
  "```",
].join("\n");

function clientList(ctx) {
  return ctx.clients.map((client) => client.id).join("|");
}

function detailedCatalog(ctx) {
  return categorizedTools(ctx)
    .map(([label, tools]) =>
      [
        `**${label}:**`,
        ...tools.map(
          (tool) =>
            `- \`${tool.name}\`: ${prose(toolSummary(tool))}${paramsClause(tool)}`,
        ),
      ].join("\n"),
    )
    .join("\n\n");
}

function namesCatalog(ctx) {
  return categorizedTools(ctx)
    .map(
      ([label, tools]) =>
        `${label}: ${tools.map((tool) => `\`${tool.name}\``).join(", ")}`,
    )
    .join("\n\n");
}

// One entry per block name. `type` is the freshness block category used by
// the test suite: version pins, install commands, release receipts, MCP
// tool catalogs, setup-client surfaces, CLI surfaces, and sitemap dates.
export const GENERATORS = new Map([
  [
    "public-release-version",
    {
      type: "version-pin",
      render: (ctx) =>
        [
          `export const PUBLIC_RELEASE_VERSION = "${ctx.version}";`,
          "export const PUBLIC_RELEASE_TAG = `v${PUBLIC_RELEASE_VERSION}`;",
        ].join("\n"),
    },
  ],
  [
    "install-clients",
    {
      type: "install-command",
      render: (ctx) => {
        const entries = clientsWithPresentation(ctx).map((client) => {
          const { logo, launch, scope } = client.presentation;
          return [
            "  {",
            `    id: "${client.id}",`,
            `    label: "${client.label}",`,
            `    Logo: ${logo},`,
            `    preview: "phantom setup --client ${client.id} --print",`,
            `    command: "phantom setup --client ${client.id}",`,
            `    launch: ${JSON.stringify(launch)},`,
            `    config: "${client.config}",`,
            `    scope: "${scope}",`,
            "  },",
          ].join("\n");
        });
        return `const CLIENTS = [\n${entries.join("\n")}\n] as const;`;
      },
    },
  ],
  [
    "sitemap-pages",
    {
      type: "sitemap",
      render: (ctx) => {
        const rows = SITEMAP_PAGES.map(
          ([path, rel]) =>
            `  { path: "${path}", modified: "${pageModified(ctx, rel)}" },`,
        );
        return `const pages = [\n${rows.join("\n")}\n] as const;`;
      },
    },
  ],
  [
    "docs-sitemap",
    {
      type: "sitemap",
      render: (ctx) => {
        const entries = [
          ...SITEMAP_PAGES.map(([path, rel]) => ({
            path,
            modified: pageModified(ctx, rel),
          })),
          ...ctx.docsCatalog.map((entry) => ({
            path: `/docs/${entry.slug}`,
            modified: entry.modified,
          })),
        ];
        return entries
          .map(({ path, modified }) =>
            [
              "  <url>",
              `    <loc>https://phm.dev${path}</loc>`,
              `    <lastmod>${modified}</lastmod>`,
              ...(path === "/" ? ["    <priority>1.0</priority>"] : []),
              "  </url>",
            ].join("\n"),
          )
          .join("\n");
      },
    },
  ],
  [
    "release-receipt",
    { type: "release-receipt", render: receiptText },
  ],
  [
    "install-homebrew",
    { type: "install-command", render: () => HOMEBREW_FENCE },
  ],
  [
    "release-assets",
    {
      type: "version-pin",
      render: (ctx) =>
        [
          `### Exact ${ctx.tag} GitHub assets`,
          ...RELEASE_ARTIFACTS.map(
            ([label, artifact]) =>
              `${label}: ${RELEASES}/download/${ctx.tag}/${artifact}`,
          ),
        ].join("\n"),
    },
  ],
  [
    "release-asset-pin",
    {
      type: "version-pin",
      render: (ctx) =>
        [
          `For the current macOS, Linux, or Windows release, select the exact \`${ctx.tag}\``,
          "archive for your architecture from the release, download its adjacent",
          "`.sha256` sidecar, verify it, and place both release executables on",
          "PATH.",
        ].join("\n"),
    },
  ],
  [
    "source-build",
    {
      type: "install-command",
      render: (ctx) =>
        [
          "```",
          "git clone https://github.com/ashlrai/phantom-secrets.git",
          "cd phantom-secrets",
          `git checkout ${ctx.evidence.sourceCommit}`,
          "cargo build --release --locked --bin phantom --bin phantom-mcp",
          "```",
        ].join("\n"),
    },
  ],
  [
    "install-binaries-pin",
    { type: "version-pin", render: binariesPin },
  ],
  [
    "header-install-pin",
    {
      type: "version-pin",
      render: (ctx) =>
        `Install: use the exact checksum-verified \`${ctx.tag}\` GitHub assets below on macOS, Linux, and Windows.`,
    },
  ],
  [
    "header-mcp-invocation",
    {
      type: "install-command",
      render: (ctx) =>
        `MCP: after installing both release binaries, run \`phantom setup --client ${clientList(ctx)}\`.`,
    },
  ],
  [
    "site-llmsfull-setup-pin",
    {
      type: "install-command",
      render: (ctx) =>
        `Setup: install both reviewed \`${ctx.tag}\` GitHub release binaries, then run \`phantom setup --client claude\``,
    },
  ],
  [
    "mcp-setup-invocation",
    {
      type: "install-command",
      render: (ctx) =>
        `Run \`phantom setup --client ${clientList(ctx)}\` after installing both\n\`${ctx.tag}\` GitHub release binaries.`,
    },
  ],
  [
    "mcp-clients-feature",
    {
      type: "install-command",
      render: (ctx) =>
        `- Multi-IDE setup: \`phantom setup --client ${clientList(ctx)}\` writes the right MCP config for each AI tool`,
    },
  ],
  [
    "setup-clients-feature",
    {
      type: "install-command",
      render: (ctx) =>
        `- \`phantom setup --client ${clientList(ctx)}\` writes the right MCP config file per AI tool; \`--print\` emits the snippet to stdout for any other client.`,
    },
  ],
  [
    "site-llms-mcp-setup",
    {
      type: "install-command",
      render: (ctx) => {
        const rows = clientsWithPresentation(ctx).map(
          (client) =>
            `| ${client.label} | \`phantom setup --client ${client.id}\` | \`${client.config}\`${client.presentation.tableNote ?? ""} |`,
        );
        return [
          "| Editor | Command | Writes to |",
          "|---|---|---|",
          ...rows,
          "| Other | `phantom setup --client claude --print` | snippet to stdout |",
        ].join("\n");
      },
    },
  ],
  [
    "docs-llms-mcp-setup",
    {
      type: "install-command",
      render: (ctx) => {
        const rows = clientsWithPresentation(ctx).map(
          (client) =>
            `- ${client.label}: \`phantom setup --client ${client.id}\` (writes ${client.config}${client.presentation.listNote ?? ""})`,
        );
        return [
          ...rows,
          "- Generic: `phantom setup --client claude --print` (snippet to stdout)",
        ].join("\n");
      },
    },
  ],
  [
    "site-llmsfull-mcp-setup",
    {
      type: "install-command",
      render: (ctx) =>
        clientsWithPresentation(ctx)
          .map(
            (client) =>
              `${client.label}:\n  phantom setup --client ${client.id}`,
          )
          .join("\n\n"),
    },
  ],
  [
    "docs-llmsfull-mcp-setup",
    {
      type: "install-command",
      render: (ctx) =>
        clientsWithPresentation(ctx)
          .map(
            (client) =>
              `**${client.label}:** \`phantom setup --client ${client.id}\``,
          )
          .join("\n\n"),
    },
  ],
  [
    "llms-tool-catalog",
    { type: "tool-catalog", render: namesCatalog },
  ],
  [
    "llmsfull-tool-catalog",
    { type: "tool-catalog", render: stanzaCatalog },
  ],
  [
    "docs-llmsfull-tool-catalog",
    { type: "tool-catalog", render: detailedCatalog },
  ],
  [
    "cli-surface",
    {
      type: "cli-surface",
      render: (ctx) =>
        ctx.cliGroups
          .map(
            (group) =>
              `${group.heading}: \`${group.commands.join(" · ")}\``,
          )
          .join(" | "),
    },
  ],
  [
    "cli-surface-heading",
    {
      type: "cli-surface",
      render: (ctx) =>
        `## CLI surface (--help is grouped: ${ctx.cliGroups.map((group) => group.heading).join(" · ")})`,
    },
  ],
  [
    "release-identity",
    {
      type: "release-receipt",
      render: (ctx) =>
        `- Immutable \`${ctx.tag}\` release identity:\n  \`${ctx.evidence.sourceCommit}\`.`,
    },
  ],
]);

// file (repo-root relative) -> ordered block names that file must carry.
// Generating the same block name in several files is intentional: it keeps
// shared facts byte-identical across the docs and site copies.
export const TARGETS = new Map([
  ["apps/web/src/lib/public-release.ts", ["public-release-version"]],
  ["apps/web/src/components/landing/Install.tsx", ["install-clients"]],
  ["apps/web/src/app/sitemap.ts", ["sitemap-pages"]],
  [
    "apps/web/public/llms.txt",
    [
      "release-receipt",
      "install-homebrew",
      "release-asset-pin",
      "site-llms-mcp-setup",
      "install-binaries-pin",
      "llms-tool-catalog",
      "cli-surface",
      "setup-clients-feature",
      "release-identity",
    ],
  ],
  [
    "apps/web/public/llms-full.txt",
    [
      "release-receipt",
      "header-install-pin",
      "header-mcp-invocation",
      "install-homebrew",
      "release-assets",
      "source-build",
      "site-llmsfull-setup-pin",
      "install-binaries-pin",
      "llmsfull-tool-catalog",
      "site-llmsfull-mcp-setup",
    ],
  ],
  [
    "docs/llms.txt",
    [
      "release-receipt",
      "install-homebrew",
      "release-asset-pin",
      "docs-llms-mcp-setup",
      "install-binaries-pin",
      "llms-tool-catalog",
      "cli-surface-heading",
      "mcp-clients-feature",
      "release-identity",
    ],
  ],
  [
    "docs/llms-full.txt",
    [
      "release-receipt",
      "header-install-pin",
      "header-mcp-invocation",
      "install-homebrew",
      "release-assets",
      "source-build",
      "mcp-setup-invocation",
      "install-binaries-pin",
      "docs-llmsfull-mcp-setup",
      "docs-llmsfull-tool-catalog",
    ],
  ],
  ["docs/sitemap.xml", ["docs-sitemap"]],
]);

function markerStyle(file) {
  const style = STYLE_BY_EXTENSION[extname(file)];
  if (!style) {
    throw new Error(`no freshness marker style registered for ${file}`);
  }
  return MARKER_STYLES[style];
}

// Re-render every marked block in `content`. Returns { content, drift };
// `drift` lists blocks whose previous content differed from the rendered
// output. Marker errors (unknown names, missing ends, nested or stray
// markers, duplicated blocks, markers in a non-target style) are hard
// errors: the file is left untouched and the caller fails.
export function applyBlocks(content, file, ctx) {
  const style = markerStyle(file);
  const expected = TARGETS.get(file);
  if (!expected) {
    throw new Error(`${file} is not a freshness target`);
  }
  const seen = new Set();
  const drift = [];
  const lines = content.split("\n");
  const out = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const begin = line.match(style.begin);
    if (!begin) {
      if (ANY_MARKER.test(line)) {
        // Any marker-looking line that this file's begin pattern did not
        // match is a hard error: it is either a stray end marker or a
        // marker written in the wrong comment style.
        throw new Error(`${file}:${index + 1}: unmatched freshness marker`);
      }
      out.push(line);
      continue;
    }

    const name = begin[1];
    const generator = GENERATORS.get(name);
    if (!generator) {
      throw new Error(`${file}:${index + 1}: unknown freshness block ${name}`);
    }
    if (!expected.includes(name)) {
      throw new Error(
        `${file}:${index + 1}: block ${name} is not registered for this file`,
      );
    }
    if (seen.has(name)) {
      throw new Error(`${file}:${index + 1}: duplicate freshness block ${name}`);
    }
    seen.add(name);
    out.push(line);

    const prior = [];
    let end = -1;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const cursorLine = lines[cursor];
      if (style.end.test(cursorLine)) {
        end = cursor;
        break;
      }
      if (style.begin.test(cursorLine)) {
        throw new Error(
          `${file}:${cursor + 1}: nested freshness block ${cursorLine.trim()}`,
        );
      }
      if (ANY_MARKER.test(cursorLine)) {
        throw new Error(
          `${file}:${cursor + 1}: stray freshness marker inside block ${name}`,
        );
      }
      prior.push(cursorLine);
    }
    if (end === -1) {
      throw new Error(`${file}:${index + 1}: block ${name} has no fresh:end`);
    }

    const rendered = generator.render(ctx, file);
    const next = rendered.split("\n");
    if (rendered === "" || next.some((entry) => ANY_MARKER.test(entry))) {
      throw new Error(`${file}: generator for ${name} produced invalid content`);
    }
    if (prior.join("\n") !== rendered) {
      drift.push({ block: name, expected: rendered, actual: prior.join("\n") });
    }
    out.push(...next, lines[end]);
    index = end;
  }

  const missing = expected.filter((name) => !seen.has(name));
  if (missing.length > 0) {
    throw new Error(`${file}: missing freshness blocks: ${missing.join(", ")}`);
  }
  return { content: out.join("\n"), drift };
}
