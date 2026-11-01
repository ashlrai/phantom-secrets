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

test("copy checklist tracks each displayed install command and its cleanup", () => {
  const doc = fs.readFileSync(path.join(__dirname, "../../../docs/quickstart-copy-checklist.md"), "utf8");
  let selected = "macOS";
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return { ...React, useState: (initial) => { assert.equal(initial, "macOS"); return [selected, () => {}]; } };
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });
  assert.deepEqual(find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children),
    ["macOS", "Windows", "Linux"]);
  for (const [platform, fragments] of [
    ["macOS", ["set -euo pipefail", "umask 077", '"${TMPDIR:-/tmp}/phantom-install.XXXXXX"', '"$phantom_installer"', '"$phantom_stage"', "trap '", "shasum -a 256 -c -"]],
    ["Windows", ["$env:TEMP", "Get-FileHash -Algorithm SHA256", "-LiteralPath", "& $Installer", "finally", "Remove-Item"]],
    ["Linux", ["set -euo pipefail", "umask 077", '"${TMPDIR:-/tmp}/phantom-install.XXXXXX"', '"$phantom_installer"', '"$phantom_stage"', "trap '", "sha256sum -c -"]],
  ]) {
    selected = platform;
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const copy = find(card, (node) => typeof node.props.text === "string")[0];
    for (const fragment of fragments) assert.ok(copy.props.text.includes(fragment), `${platform}: ${fragment}`);
    const verify = copy.props.text.indexOf(platform === "Windows" ? "Get-FileHash" : platform === "macOS" ? "shasum" : "sha256sum");
    const execute = copy.props.text.indexOf(platform === "Windows" ? "& $Installer" : 'bash "$phantom_installer"');
    assert.ok(verify >= 0 && execute > verify, `${platform}: verification precedes execution`);
    assert.equal(copy.props.prompt || "$", platform === "Windows" ? "PS>" : "$");
  }
  for (const fragment of [
    "macOS** is selected initially", "**Windows** or **Linux**", "Bash", "PowerShell", "`$` or `PS>`",
    '"${TMPDIR:-/tmp}/phantom-install.XXXXXX"', '"$phantom_installer"', '"$phantom_stage"',
    "single-quoted `trap`", "`set -euo pipefail`", "`umask 077`", "`$env:TEMP`", "`-LiteralPath`",
    "shasum -a 256 -c -", "sha256sum -c -", "Get-FileHash -Algorithm SHA256", "before executing",
    "exit trap attempts", "once the trap", "`finally` attempts", "not guaranteed", "not the install directory",
    "`phantom --version`", "`phantom-mcp --version`", "`phantom init`",
  ]) assert.ok(doc.includes(fragment), `checklist: ${fragment}`);
  assert.match(fs.readFileSync(path.join(__dirname, "../../../docs/README.md"), "utf8"), /\]\(quickstart-copy-checklist\.md\)/);
});
