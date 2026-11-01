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
const guide = fs.readFileSync(path.join(docs, "quickstart-temp-directory-usage.md"), "utf8");
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

test("guide accounts for every displayed platform and links from the docs index", () => {
  const platforms = find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children);
  assert.deepEqual(platforms, ["macOS", "Windows", "Linux"]);
  for (const platform of platforms) section(platform);
  assert.match(guide, /copying it does not create a directory/);
  assert.match(fs.readFileSync(path.join(docs, "README.md"), "utf8"), /\]\(quickstart-temp-directory-usage\.md\)/);
});

test("Unix guide describes creation before download, use, and cleanup", () => {
  for (const [platform, checksum] of [["macOS", "shasum -a 256 -c -"], ["Linux", "sha256sum -c -"]]) {
    const command = commands(platform)[0];
    ordered(command, ["umask 077", 'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"',
      'phantom_installer="$phantom_stage/install.sh"', "trap '", "rm -f", "rmdir", "curl ", checksum,
      'bash "$phantom_installer"', 'bin/phantom" --version', 'bin/phantom-mcp" --version']);
    assert.ok(section(platform).includes(`\`${checksum}\``));
  }
  const mac = section("macOS");
  for (const phrase of ["Each run", "before downloading", "`TMPDIR`", "`/tmp`", "unset or empty",
    "does not retry", "`install.sh`", "`EXIT`", "not the installation destination", "Cleanup is best effort"]) {
    assert.ok(mac.includes(phrase), phrase);
  }
  assert.match(section("Linux"), /same .*template, parent selection, and fallback as macOS/s);
});

test("Windows guide distinguishes path assignment from download and cleanup", () => {
  const command = commands("Windows")[0];
  ordered(command, ["$Installer = Join-Path $env:TEMP", "[Guid]::NewGuid()", "try {", "Invoke-WebRequest",
    "-OutFile $Installer", "Get-FileHash", "& $Installer", "phantom.exe", "phantom-mcp.exe", "finally", "Remove-Item"]);
  assert.doesNotMatch(command, /mktemp|New-Item/);
  const windows = section("Windows");
  for (const phrase of ["does not create a temporary directory", "`$env:TEMP`", "creates neither a directory nor a file",
    "`Invoke-WebRequest`", "`Get-FileHash`", "`finally`", "cleanup is not guaranteed", "no fallback"]) {
    assert.ok(windows.includes(phrase), phrase);
  }
});

test("later displayed commands are distinguished from program internals", () => {
  assert.deepEqual(commands("macOS").slice(1), ["phantom --version\nphantom-mcp --version", "phantom init"]);
  const later = section("Later commands and scope");
  for (const phrase of ["`phantom --version`", "`phantom-mcp --version`", "`phantom init`", "command line does not explicitly create", "internal temporary files or directories", "archive staging"]) {
    assert.ok(later.includes(phrase), phrase);
  }
});
