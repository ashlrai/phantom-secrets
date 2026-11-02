const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");

function load(file, localRequire = require) {
  const source = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", compiled)(exports, localRequire);
  return exports;
}

function find(element, predicate) {
  if (!React.isValidElement(element)) return [];
  return [
    ...(predicate(element) ? [element] : []),
    ...React.Children.toArray(element.props.children).flatMap((child) => find(child, predicate)),
  ];
}

const docs = path.join(__dirname, "../../../docs");
const guide = fs.readFileSync(path.join(docs, "quickstart-staging-comparison.md"), "utf8");
const release = load("src/lib/public-release.ts");
let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: () => [selected, () => {}] };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return release;
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});

function command(platform) {
  selected = platform;
  // The platform card's copy button renders first; the two shared STEPS
  // commands ("phantom --version…" and "phantom init") follow it.
  const commands = find(QuickStart(), (node) => typeof node.props.text === "string");
  return commands[0].props.text;
}

// The guide marks pinned values with placeholders so its reference lines are
// not copyable commands; normalize the displayed commands the same way before
// comparing line by line.
function normalize(text) {
  return text
    .split(release.PUBLIC_RELEASE_SOURCE_COMMIT).join("<pinned source commit>")
    .split(release.PUBLIC_RELEASE_UNIX_INSTALLER_SHA256).join("<pinned installer digest>")
    .split(release.PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256).join("<pinned installer digest>")
    .split(release.PUBLIC_RELEASE_TAG).join("<release tag>");
}

const normalized = {
  macOS: normalize(command("macOS")).split("\n"),
  Windows: normalize(command("Windows")).split("\n"),
  Linux: normalize(command("Linux")).split("\n"),
};

function section(name) {
  const value = guide.split(`## ${name}\n`)[1]?.split("\n## ")[0];
  assert.ok(value, `missing ${name} section`);
  return value;
}

function fenced(sectionText, fence) {
  const block = sectionText.split(`\`\`\`${fence}\n`)[1]?.split("\n```")[0];
  assert.ok(block, `missing ${fence} block`);
  return block.split("\n").filter((line) => line.length > 0);
}

test("three platform cards display exactly two distinct staging snippets", () => {
  assert.deepEqual(find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children),
    ["macOS", "Windows", "Linux"]);
  assert.equal(normalized.macOS.length, 12, "Unix snippet line count");
  assert.equal(normalized.Windows.length, 18, "Windows block line count");

  // macOS and Linux share every line except the checksum tool.
  const differing = normalized.macOS.filter((line, index) => line !== normalized.Linux[index]);
  assert.equal(differing.length, 1, "one platform-specific line between macOS and Linux");
  assert.equal(normalized.Linux.filter((line, index) => line !== normalized.macOS[index]).length, 1);
  assert.match(differing[0], /\| shasum -a 256 -c -$/);
  assert.match(normalized.Linux.find((line, index) => line !== normalized.macOS[index]), /\| sha256sum -c -$/);

  // No line is shared verbatim between the Unix subshell and the Windows block.
  const windows = new Set(normalized.Windows);
  assert.deepEqual([...new Set(normalized.macOS)].filter((line) => windows.has(line)), []);

  for (const fragment of ["**two**", "distinct staging snippets", "twelve-line", "eighteen-line",
    "shared verbatim", "no line", "platform-specific"]) {
    assert.ok(guide.includes(fragment), `guide: ${fragment}`);
  }
});

test("the documented Unix snippet quotes every displayed line", () => {
  const block = fenced(section("Snippet one: the Unix subshell (macOS and Linux)"), "sh");
  const annotated = block.filter((line) => /\s+# (?:macOS|Linux) only$/.test(line));
  assert.equal(annotated.length, 2, "both checksum variants are annotated");
  const quoted = block.map((line) => line.replace(/\s+# (?:macOS|Linux) only$/, ""));
  assert.equal(quoted.length, 13, "eleven shared lines plus two checksum variants");
  for (const [index, line] of block.entries()) {
    const stripped = quoted[index];
    if (line.endsWith("# macOS only")) {
      assert.ok(normalized.macOS.includes(stripped), `macOS line: ${stripped}`);
      assert.ok(!normalized.Linux.includes(stripped), `macOS line must not appear on Linux: ${stripped}`);
    } else if (line.endsWith("# Linux only")) {
      assert.ok(normalized.Linux.includes(stripped), `Linux line: ${stripped}`);
      assert.ok(!normalized.macOS.includes(stripped), `Linux line must not appear on macOS: ${stripped}`);
    } else {
      assert.ok(normalized.macOS.includes(stripped), `shared line: ${stripped}`);
      assert.ok(normalized.Linux.includes(stripped), `shared line: ${stripped}`);
    }
  }
  // Coverage: every displayed Unix line appears in the documented block.
  for (const line of normalized.macOS) assert.ok(quoted.includes(line), `documented: ${line}`);
  for (const line of normalized.Linux) assert.ok(quoted.includes(line), `documented: ${line}`);
});

test("the documented Windows block quotes every displayed line", () => {
  const block = fenced(section("Snippet two: the Windows PowerShell block"), "powershell");
  assert.equal(block.length, normalized.Windows.length);
  for (const line of block) {
    assert.ok(normalized.Windows.includes(line), `Windows line: ${line}`);
  }
  for (const line of normalized.Windows) {
    assert.ok(block.includes(line), `documented: ${line}`);
  }
});

test("shared steps map to the actual platform-specific lines", () => {
  const table = section("Shared steps, platform-specific lines");
  for (const step of ["Group the block", "Stop on failure", "Restrict staging permissions",
    "Unique staging under the temp root", "Name the staged installer",
    "Arm cleanup before downloading", "Download the pinned script",
    "Verify the fixed SHA-256 digest", "Run the verified installer",
    "Check both installed binaries"]) {
    assert.ok(table.includes(step), `step row: ${step}`);
  }

  // Fragments the guide calls platform-specific behave that way in the
  // displayed commands: present in one snippet, absent from the other.
  const unixText = normalized.macOS.join("\n");
  const windowsText = normalized.Windows.join("\n");
  for (const fragment of ["set -euo pipefail", "umask 077", "${TMPDIR:-/tmp}",
    "mktemp -d", "phantom-install.XXXXXX", "trap 'rm -f", "rmdir",
    "curl --fail --location", "install.sh", 'bash "$phantom_installer"',
    "$HOME/.phantom-secrets/bin/phantom", "shasum -a 256 -c -"]) {
    assert.ok(unixText.includes(fragment), `Unix command: ${fragment}`);
    assert.ok(!windowsText.includes(fragment), `Windows must not contain: ${fragment}`);
  }
  for (const fragment of ["$ErrorActionPreference = 'Stop'", "Join-Path $env:TEMP",
    "[Guid]::NewGuid()", "Invoke-WebRequest", "Get-FileHash -Algorithm SHA256",
    "install.ps1", "& $Installer", "if (-not $?)", "phantom.exe", "phantom-mcp.exe",
    "$env:USERPROFILE", "Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue"]) {
    assert.ok(windowsText.includes(fragment), `Windows command: ${fragment}`);
    assert.ok(!unixText.includes(fragment), `Unix must not contain: ${fragment}`);
  }
  const linuxChecksum = `printf '%s  %s\\n' <pinned installer digest> "$phantom_installer" | sha256sum -c -`;
  assert.ok(normalized.Linux.includes(linuxChecksum), "Linux checksum line");
  assert.ok(!normalized.macOS.some((line) => line.includes("sha256sum")), "macOS must not contain sha256sum");
  for (const fragment of ["`umask 077`", "`${TMPDIR:-/tmp}`", "`rmdir`",
    "`$Expected`/`$Actual`", "`if (-not $?) { throw … }`", "`[Guid]::NewGuid()`"]) {
    assert.ok(guide.includes(fragment), `guide names: ${fragment}`);
  }
});

test("the guide is discoverable and stays in scope", () => {
  assert.match(fs.readFileSync(path.join(docs, "README.md"), "utf8"),
    /\]\(quickstart-staging-comparison\.md\)/);
  for (const fragment of ["QuickStart.tsx", "public-release.ts",
    "<release tag>", "<pinned source commit>", "<pinned installer digest>",
    "not the install directory", "not guaranteed",
    "quickstart-staging-lifecycle.md", "quickstart-temp-cleanup-review.md",
    "installer-staging.md", "getting-started.md#exact-github-assets-macos-linux-and-windows"]) {
    assert.ok(guide.includes(fragment), `guide: ${fragment}`);
  }
  assert.doesNotMatch(guide, /phantom init|phantom (?:add|remove|rotate|sync)\b/i);
});
