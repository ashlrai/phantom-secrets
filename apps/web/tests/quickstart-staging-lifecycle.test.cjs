const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const React = require("react");
const ts = require("typescript");

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

function ordered(text, fragments) {
  let position = 0;
  for (const fragment of fragments) {
    const index = text.indexOf(fragment, position);
    assert.notEqual(index, -1, `missing or out of order: ${fragment}`);
    position = index + fragment.length;
  }
}

const docs = path.join(__dirname, "../../../docs");
const guide = fs.readFileSync(path.join(docs, "quickstart-staging-lifecycle.md"), "utf8");
let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: () => [selected, () => {}] };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});

function section(name) {
  const value = guide.split(`## ${name}\n`)[1]?.split("\n## ")[0];
  assert.ok(value, `missing ${name} section`);
  return value;
}

function commands(platform) {
  selected = platform;
  return find(QuickStart(), (node) => typeof node.props.text === "string").map((node) => node.props.text);
}

test("lifecycle covers each platform and is discoverable", () => {
  assert.deepEqual(find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children),
    ["macOS", "Windows", "Linux"]);
  for (const platform of ["macOS", "Windows", "Linux"]) section(platform);
  assert.match(fs.readFileSync(path.join(docs, "README.md"), "utf8"), /\]\(quickstart-staging-lifecycle\.md\)/);
});

test("Unix lifecycle matches the displayed ordering and cleanup limits", () => {
  for (const [platform, checksum] of [["macOS", "shasum -a 256 -c -"], ["Linux", "sha256sum -c -"]]) {
    ordered(commands(platform)[0], ["set -euo pipefail", "umask 077",
      'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"',
      'phantom_installer="$phantom_stage/install.sh"',
      `trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT`,
      "curl ", checksum, 'bash "$phantom_installer"', 'bin/phantom" --version', 'bin/phantom-mcp" --version']);
    assert.ok(section(platform).includes(`\`${checksum}\``));
  }
  for (const phrase of ["unset or empty", "not retried", "`EXIT`", "if reached", "empty directory",
    "no recursive removal", "success receipt", "before", "filesystem errors", "extra contents"]) {
    assert.ok(section("macOS").includes(phrase), phrase);
  }
  assert.match(section("Linux"), /same best-effort removal/i);
});

test("Windows and later commands do not explicitly create a staging directory", () => {
  const [windows, ...later] = commands("Windows");
  ordered(windows, ["$Installer = Join-Path $env:TEMP", "[Guid]::NewGuid()", "try {", "Invoke-WebRequest",
    "-OutFile $Installer", "Get-FileHash", "& $Installer", "phantom.exe", "phantom-mcp.exe", "finally {",
    "Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue"]);
  assert.doesNotMatch(windows, /mktemp|New-Item/);
  for (const phrase of ["creates neither a directory nor a file", "no staging directory", "no fallback",
    "does not remove that parent directory", "removal failure"]) assert.ok(section("Windows").includes(phrase), phrase);
  assert.deepEqual(later, ["phantom --version\nphantom-mcp --version", "phantom init"]);
  assert.match(section("Later command blocks and scope"), /no explicit staging directory or cleanup/);
  assert.match(section("Later command blocks and scope"), /internal temporary files/);
});
