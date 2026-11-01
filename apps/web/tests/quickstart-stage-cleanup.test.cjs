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
const guide = fs.readFileSync(path.join(docs, "quickstart-stage-cleanup.md"), "utf8");
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

function command(platform) {
  selected = platform;
  const card = find(QuickStart(), (node) => node.type === "article")[0];
  return find(card, (node) => typeof node.props.text === "string")[0].props.text;
}

test("guide covers every displayed platform and is discoverable", () => {
  assert.deepEqual(find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children),
    ["macOS", "Windows", "Linux"]);
  for (const platform of ["macOS", "Windows", "Linux"]) section(platform);
  assert.match(fs.readFileSync(path.join(docs, "README.md"), "utf8"), /\]\(quickstart-stage-cleanup\.md\)/);
  assert.match(guide, /Selecting or copying a\ncommand creates nothing/);
});

test("Unix staging and cleanup match both displayed commands", () => {
  for (const [platform, checksum] of [["macOS", "shasum -a 256 -c -"], ["Linux", "sha256sum -c -"]]) {
    const displayed = command(platform);
    const assignment = displayed.split("\n").find((line) => line.startsWith("phantom_stage="));
    assert.ok(guide.includes(`\n${assignment}\n`));
    ordered(displayed, ["umask 077", assignment, 'phantom_installer="$phantom_stage/install.sh"',
      "trap '", 'rm -f -- "$phantom_installer"', 'rmdir -- "$phantom_stage"', "EXIT", "curl ",
      checksum, 'bash "$phantom_installer"', 'bin/phantom" --version', 'bin/phantom-mcp" --version']);
    assert.ok(section(platform).includes(`\`${checksum}\``));
  }
  for (const phrase of ["unset or empty", "no retry", "`EXIT` trap", "empty directory", "best effort",
    "before trap installation", "extra directory contents"]) assert.ok(section("macOS").includes(phrase), phrase);
  assert.match(section("Linux"), /same best-effort cleanup/);
});

test("Windows stages a file and attempts cleanup in finally", () => {
  const displayed = command("Windows");
  ordered(displayed, ["$Installer = Join-Path $env:TEMP", "[Guid]::NewGuid()", "try {", "Invoke-WebRequest",
    "-OutFile $Installer", "Get-FileHash", "& $Installer", "phantom.exe", "phantom-mcp.exe", "finally {",
    "Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue"]);
  assert.doesNotMatch(displayed, /mktemp|New-Item/);
  for (const phrase of ["creates neither a directory nor", "creates no staging directory", "no\nfallback",
    "`finally`", "Removal errors are suppressed", "can leave the file"]) assert.ok(section("Windows").includes(phrase), phrase);
});
