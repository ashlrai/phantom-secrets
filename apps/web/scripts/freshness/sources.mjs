#!/usr/bin/env node

// Source-of-truth readers for the site freshness generator. Every marked
// `fresh:` block is rendered from these values only. When the sources
// disagree the repository's own release metadata is inconsistent, so
// loading fails closed instead of picking a winner.
//
// This mirrors scripts/freshness/sources.mjs (RQ-FRESH-GEN-PS) so the two
// generators can merge once that stack lands; the site generator adds the
// sources the site needs: the MCP tool catalog, the CLI command groups,
// the `phantom setup --client` enum, the bound release evidence record,
// and git-derived sitemap dates.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SEMVER =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function read(root, rel) {
  return readFileSync(join(root, rel), "utf8");
}

function readPackage(root, rel) {
  const parsed = JSON.parse(read(root, rel));
  if (typeof parsed.name !== "string" || parsed.name === "") {
    throw new Error(`${rel} has no package name`);
  }
  if (typeof parsed.version !== "string" || !SEMVER.test(parsed.version)) {
    throw new Error(`${rel} version is missing or not semver`);
  }
  return { name: parsed.name, version: parsed.version };
}

// GitHub renders `## [0.7.9] - 2026-09-06` under the `#079---2026-09-06`
// anchor: lowercase, drop characters outside [a-z0-9 -], fold spaces to
// hyphens.
export function githubAnchor(headingText) {
  return headingText
    .toLowerCase()
    .replace(/[^a-z0-9 -]/g, "")
    .replace(/ /g, "-");
}

function kebab(identifier) {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .toLowerCase();
}

function git(root, args) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

// The published MCP catalog mirrored from the runtime `tools/list`
// response. The release schema smoke pins this file to the runtime, so it
// is the repo-side canonical catalog for generated tool lists.
function mcpTools(root) {
  const server = JSON.parse(read(root, "mcp-registry/server.json"));
  if (!Array.isArray(server.tools) || server.tools.length === 0) {
    throw new Error("mcp-registry/server.json has no tools array");
  }
  const seen = new Set();
  const tools = server.tools.map((tool) => {
    if (typeof tool.name !== "string" || !tool.name.startsWith("phantom_")) {
      throw new Error(`mcp-registry/server.json has a malformed tool name`);
    }
    if (seen.has(tool.name)) {
      throw new Error(`mcp-registry/server.json repeats tool ${tool.name}`);
    }
    seen.add(tool.name);
    if (typeof tool.description !== "string" || tool.description === "") {
      throw new Error(`mcp-registry/server.json tool ${tool.name} has no description`);
    }
    const schema = tool.inputSchema ?? {};
    const properties = schema.properties ?? {};
    const required = Array.isArray(schema.required) ? schema.required : [];
    const gate = new Set(["confirm", "approval_token"]);
    const params = [
      // Required parameters first, in `required` order, then optional
      // parameters in schema order. The confirmation gates always come last,
      // matching the documented `..., confirm, approval_token` convention.
      ...required.filter((name) => !gate.has(name)),
      ...Object.keys(properties).filter(
        (name) => !gate.has(name) && !required.includes(name),
      ),
      ...["confirm", "approval_token"].filter((name) =>
        Object.hasOwn(properties, name),
      ),
    ];
    const optional = new Set(
      Object.keys(properties).filter((name) => !required.includes(name)),
    );
    return {
      name: tool.name,
      description: tool.description.replace(/\s+/g, " ").trim(),
      params,
      optional,
      properties,
    };
  });
  return tools;
}

// `commands::setup::Client` is the canonical list of `--client` values:
// the value name, the display label from `Client::label`, and the config
// path its doc comment declares (which must also appear as a literal in
// the setup implementation so the comment cannot drift silently).
function setupClients(root) {
  const source = read(root, "crates/phantom-cli/src/commands/setup.rs");
  const enumMatch = source.match(/pub enum Client \{([\s\S]*?)\n\}/);
  if (!enumMatch) {
    throw new Error("setup.rs has no `pub enum Client` block");
  }
  const body = enumMatch[1];

  const labelBody = source.match(/fn label\(self\)[^{]*\{([\s\S]*?)\n    \}/);
  if (!labelBody) {
    throw new Error("setup.rs has no `Client::label` match");
  }
  const labels = new Map();
  for (const match of labelBody[1].matchAll(
    /Client::([A-Za-z]+)\s*=>\s*"([^"]+)"/g,
  )) {
    labels.set(match[1], match[2]);
  }

  const clients = [];
  const variantRe =
    /(?:\/\/\/(?<doc>[^\n]*)\n\s*)?(?:#\[value\((?<attrs>[^\]]*)\)\]\n\s*)?(?<variant>[A-Z][A-Za-z]*),/g;
  for (const match of body.matchAll(variantRe)) {
    const { doc = "", attrs = "", variant } = match.groups;
    const nameMatch = attrs.match(/name\s*=\s*"([^"]+)"/);
    const id = nameMatch ? nameMatch[1] : kebab(variant);
    const label = labels.get(variant);
    if (!label) {
      throw new Error(`setup.rs Client::label() has no arm for ${variant}`);
    }
    const pathMatch = doc.match(/(~\/[^\s`']+|\.[a-z0-9_][a-z0-9_./]*)/);
    if (!pathMatch) {
      throw new Error(
        `setup.rs Client::${variant} doc comment declares no config path`,
      );
    }
    const config = pathMatch[1].replace(/[.,;:)]+$/, "");
    const repoLiteral = config.startsWith("~/") ? config.slice(2) : config;
    if (!source.includes(`"${repoLiteral}"`)) {
      throw new Error(
        `setup.rs Client::${variant} doc path ${config} is not a literal in the implementation`,
      );
    }
    clients.push({ id, label, config });
  }
  if (clients.length === 0) {
    throw new Error("setup.rs Client enum parsed to zero clients");
  }
  return clients;
}

// The top-level clap command surface, grouped by `next_help_heading`,
// hidden variants excluded. This is exactly what `phantom --help` prints.
function cliGroups(root) {
  const source = read(root, "crates/phantom-cli/src/main.rs");
  const enumStart = source.search(/\nenum Commands \{/);
  if (enumStart === -1) {
    throw new Error("main.rs has no `enum Commands` block");
  }
  const bodyStart = source.indexOf("{", enumStart);
  let depth = 0;
  let bodyEnd = -1;
  for (let i = bodyStart; i < source.length; i += 1) {
    if (source[i] === "{") depth += 1;
    else if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        bodyEnd = i;
        break;
      }
    }
  }
  if (bodyEnd === -1) {
    throw new Error("main.rs `enum Commands` has no closing brace");
  }

  const groups = [];
  let pending = { heading: null, name: null, hidden: false, attr: "" };
  let inAttr = false;
  for (const line of source.slice(bodyStart + 1, bodyEnd).split("\n")) {
    if (inAttr) {
      pending.attr += `\n${line}`;
      if (/\)\]\s*$/.test(line)) inAttr = false;
      continue;
    }
    const variantMatch = line.match(/^    ([A-Z][A-Za-z0-9]*)[\s{,]/);
    if (variantMatch) {
      if (!pending.hidden) {
        const commandName = pending.name ?? kebab(variantMatch[1]);
        let group = groups.find(
          (entry) => entry.heading === pending.heading,
        );
        if (!group) {
          group = { heading: pending.heading, commands: [] };
          groups.push(group);
        }
        group.commands.push(commandName);
      }
      pending = { heading: pending.heading, name: null, hidden: false, attr: "" };
      continue;
    }
    if (/^\s*#\[command\(/.test(line)) {
      pending.attr = line;
      if (!/\)\]\s*$/.test(line)) inAttr = true;
      const heading = pending.attr.match(/next_help_heading\s*=\s*"([^"]+)"/);
      if (heading) pending.heading = heading[1];
      const named = pending.attr.match(/\bname\s*=\s*"([^"]+)"/);
      if (named) pending.name = named[1];
      if (/\bhide\s*=\s*true\b/.test(pending.attr)) pending.hidden = true;
    }
  }

  const flat = groups.flatMap((group) => group.commands);
  if (flat.length === 0 || groups.some((group) => !group.heading)) {
    throw new Error("main.rs `enum Commands` parsed to an empty group list");
  }
  return groups;
}

// The bound release-evidence record. `public-release.ts` is the site's
// single reviewed receipt; when the release tag is resolvable locally the
// commit and tag-object constants are verified against git so a stale
// record fails closed instead of regenerating mismatched evidence.
function releaseEvidence(root, tag) {
  const source = read(root, "apps/web/src/lib/public-release.ts");
  const exported = (name) => {
    const match = source.match(
      new RegExp(`export const ${name}\\s*=\\s*"([^"]+)"`),
    );
    if (!match) {
      throw new Error(`public-release.ts is missing literal ${name}`);
    }
    return match[1];
  };

  const state = exported("PUBLIC_RELEASE_EVIDENCE_STATE");
  if (state !== "bound") {
    throw new Error(
      `public-release.ts evidence is ${state}; freshness cannot regenerate release facts until the receipt is bound`,
    );
  }
  const evidence = {
    sourceCommit: exported("PUBLIC_RELEASE_SOURCE_COMMIT"),
    tagObject: exported("PUBLIC_RELEASE_TAG_OBJECT"),
    workflowUrl: exported("PUBLIC_RELEASE_WORKFLOW_URL"),
    unixInstallerSha256: exported("PUBLIC_RELEASE_UNIX_INSTALLER_SHA256"),
    windowsInstallerSha256: exported(
      "PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256",
    ),
    unixInstallerBlobOid: exported("PUBLIC_RELEASE_UNIX_INSTALLER_BLOB_OID"),
    windowsInstallerBlobOid: exported(
      "PUBLIC_RELEASE_WINDOWS_INSTALLER_BLOB_OID",
    ),
  };
  const hex = (key, length) => {
    if (!new RegExp(`^[a-f0-9]{${length}}$`).test(evidence[key])) {
      throw new Error(`public-release.ts ${key} is not ${length} hex`);
    }
  };
  hex("sourceCommit", 40);
  hex("tagObject", 40);
  hex("unixInstallerSha256", 64);
  hex("windowsInstallerSha256", 64);
  hex("unixInstallerBlobOid", 40);
  hex("windowsInstallerBlobOid", 40);
  if (
    !/^https:\/\/github\.com\/ashlrai\/phantom-secrets\/actions\/runs\/\d+$/.test(
      evidence.workflowUrl,
    )
  ) {
    throw new Error("public-release.ts workflow URL is not a GitHub run URL");
  }

  let tagVerified = false;
  try {
    const tagCommit = git(root, ["rev-parse", `${tag}^{}`]);
    const tagObject = git(root, ["rev-parse", tag]);
    if (tagCommit !== evidence.sourceCommit) {
      throw new Error(
        `git tag ${tag} resolves to ${tagCommit} but PUBLIC_RELEASE_SOURCE_COMMIT is ${evidence.sourceCommit}`,
      );
    }
    if (tagObject !== evidence.tagObject) {
      throw new Error(
        `git tag ${tag} object is ${tagObject} but PUBLIC_RELEASE_TAG_OBJECT is ${evidence.tagObject}`,
      );
    }
    tagVerified = true;
  } catch (error) {
    if (error instanceof Error && /PUBLIC_RELEASE/.test(error.message)) {
      throw error;
    }
    // Tag absent (shallow or docs-only checkout): the checked-in evidence
    // record stands on its own, and the binding tests verify it instead.
  }
  return { ...evidence, tagVerified };
}

// `git log -1 --format=%cs -- <rel>` gives the committed lastmod date a
// sitemap entry should advertise. Fails closed when the file is unknown to
// git rather than inventing a date.
export function lastmod(root, rel) {
  const date = git(root, ["log", "-1", "--format=%cs", "--", rel]);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    throw new Error(`git has no committed date for ${rel}`);
  }
  return date;
}

// apps/web/docs-catalog.json is the site's public docs index: the Next
// sitemap takes each entry's slug and editorial `modified` date verbatim, so
// the generated static sitemap reads the same rows. Every catalog file must
// exist under docs/ so a dropped guide cannot keep a live sitemap entry.
function docsCatalog(root) {
  const catalog = JSON.parse(read(root, "apps/web/docs-catalog.json"));
  if (!Array.isArray(catalog) || catalog.length === 0) {
    throw new Error("apps/web/docs-catalog.json is not a non-empty array");
  }
  const seen = new Set();
  return catalog.map((entry) => {
    for (const field of ["slug", "file", "title", "description", "modified"]) {
      if (typeof entry?.[field] !== "string" || entry[field] === "") {
        throw new Error(`docs-catalog entry is missing ${field}`);
      }
    }
    if (!/^[a-z0-9][a-z0-9-]*$/.test(entry.slug)) {
      throw new Error(`docs-catalog slug ${entry.slug} is not a URL slug`);
    }
    if (!/^[a-z0-9][a-z0-9-]*\.md$/.test(entry.file)) {
      throw new Error(
        `docs-catalog slug ${entry.slug} file ${entry.file} is not a flat markdown name`,
      );
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(entry.modified)) {
      throw new Error(`docs-catalog slug ${entry.slug} has a bad modified date`);
    }
    if (seen.has(entry.slug)) {
      throw new Error(`docs-catalog repeats slug ${entry.slug}`);
    }
    seen.add(entry.slug);
    read(root, `docs/${entry.file}`);
    return { slug: entry.slug, modified: entry.modified };
  });
}

export function loadSources(root) {
  const cargoToml = read(root, "Cargo.toml");
  const versionMatch = cargoToml.match(
    /\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m,
  );
  if (!versionMatch) {
    throw new Error("Cargo.toml has no [workspace.package] version");
  }
  const version = versionMatch[1];
  if (!SEMVER.test(version)) {
    throw new Error(`Cargo workspace version is not semver: ${version}`);
  }

  const npmCli = readPackage(root, "npm/package.json");
  const npmMcp = readPackage(root, "npm-mcp/package.json");
  const webPackage = readPackage(root, "apps/web/package.json");
  const registry = JSON.parse(read(root, "mcp-registry/server.json"));

  const changelog = read(root, "CHANGELOG.md");
  const releaseMatch = changelog.match(
    /^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})/m,
  );
  if (!releaseMatch) {
    throw new Error("CHANGELOG.md has no released `## [x.y.z] - date` section");
  }
  const [, releaseVersion, releaseDate] = releaseMatch;

  const mismatches = [
    ["npm/package.json", npmCli.version],
    ["npm-mcp/package.json", npmMcp.version],
    ["apps/web/package.json", webPackage.version],
    ["mcp-registry/server.json", registry.version],
    ["CHANGELOG.md latest release", releaseVersion],
  ].filter(([, seen]) => seen !== version);
  if (mismatches.length > 0) {
    const detail = mismatches
      .map(([label, seen]) => `${label} is ${seen}`)
      .join("; ");
    throw new Error(
      `freshness sources disagree: Cargo workspace version is ${version}; ${detail}`,
    );
  }

  const tag = `v${version}`;
  const tools = mcpTools(root);
  const clients = setupClients(root);
  const groups = cliGroups(root);
  const evidence = releaseEvidence(root, tag);
  const catalog = docsCatalog(root);

  return {
    version,
    tag,
    releaseTagUrl: `https://github.com/ashlrai/phantom-secrets/releases/tag/${tag}`,
    npmCli,
    npmMcp,
    tools,
    clients,
    cliGroups: groups,
    evidence,
    docsCatalog: catalog,
    release: {
      version: releaseVersion,
      date: releaseDate,
      anchor: githubAnchor(`[${releaseVersion}] - ${releaseDate}`),
    },
    lastmod: (rel) => lastmod(root, rel),
  };
}
