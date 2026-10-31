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

function ordered(text, fragments) {
  let position = 0;
  for (const fragment of fragments) {
    const index = text.indexOf(fragment, position);
    assert.notEqual(index, -1, `missing or out of order: ${fragment}`);
    position = index + fragment.length;
  }
}

test("command sequence follows the displayed staging, verification, and cleanup", () => {
  const guide = fs.readFileSync(path.join(__dirname, "../../../docs/quickstart-command-sequence.md"), "utf8");
  let selected = "macOS";
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return { ...React, useState: () => [selected, () => {}] };
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });

  ordered(guide, ["## macOS and Linux", "## Windows", "## After the platform command"]);
  const unix = guide.split("## macOS and Linux\n")[1].split("## Windows\n")[0];
  ordered(unix, ["subshell", "`umask 077`", "`mktemp -d`", "`TMPDIR`", "`/tmp`", "`install.sh`", "`EXIT` trap", "downloads", "SHA-256", "`shasum -a 256 -c -`", "`sha256sum -c -`", "verified script runs", "both installed binaries", "On subshell exit", "remove the script", "empty staging", "not guaranteed"]);
  for (const [platform, digest] of [["macOS", "shasum -a 256 -c -"], ["Linux", "sha256sum -c -"]]) {
    selected = platform;
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const command = find(card, (node) => typeof node.props.text === "string")[0].props.text;
    ordered(command, ["set -euo pipefail", "umask 077", "mktemp -d", "phantom_installer=", "trap '", "rm -f", "rmdir", "curl ", digest, 'bash "$phantom_installer"', 'bin/phantom" --version', 'bin/phantom-mcp" --version']);
  }

  selected = "Windows";
  const card = find(QuickStart(), (node) => node.type === "article")[0];
  const command = find(card, (node) => typeof node.props.text === "string")[0].props.text;
  ordered(command, ["$ErrorActionPreference", "$Installer =", "$env:TEMP", "try {", "Invoke-WebRequest", "Get-FileHash", "if ($Actual -ne $Expected)", "& $Installer", "phantom.exe", "phantom-mcp.exe", "finally", "Remove-Item"]);
  const windows = guide.split("## Windows\n")[1].split("## After the platform command\n")[0];
  ordered(windows, ["errors to stop", "`$env:TEMP`", "creates neither", "`try`", "downloads", "`Get-FileHash`", "mismatch", "verified script runs", "both installed executables", "`finally`", "remove", "not guaranteed"]);

  const steps = find(QuickStart(), (node) => typeof node.props.text === "string").map((node) => node.props.text).join("\n");
  ordered(steps, ["phantom --version\nphantom-mcp --version", "phantom init"]);
  ordered(guide.split("## After the platform command\n")[1], ["`phantom --version`", "`phantom-mcp --version`", "PATH-based", "`phantom init`", "illustrative"]);
  assert.doesNotMatch(guide, /```/); // The panel remains the source of copyable commands.
  assert.match(fs.readFileSync(path.join(__dirname, "../../../docs/README.md"), "utf8"), /\]\(quickstart-command-sequence\.md\)/);
});
