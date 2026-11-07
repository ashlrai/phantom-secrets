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

test("reading guide follows the displayed platform commands and subsequent steps", () => {
  const guide = fs.readFileSync(path.join(__dirname, "../../../docs/quickstart-reading-guide.md"), "utf8");
  let selected = "macOS";
  const hooks = { ...React, useState() { return [selected, () => {}]; } };
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return hooks;
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });

  ordered(guide, ["## macOS", "## Windows", "## Linux", "## After the platform command"]);
  for (const [platform, next, checksum] of [
    ["macOS", "Windows", "shasum -a 256 -c -"],
    ["Linux", "After the platform command", "sha256sum -c -"],
  ]) {
    selected = platform;
    const card = find(QuickStart(), (element) => element.type === "article")[0];
    const command = find(card, (element) => typeof element.props.text === "string")[0].props.text;
    ordered(command, ["umask 077", "mktemp -d", "phantom_installer=", "trap ", "curl ", checksum, 'bash "$phantom_installer"', 'bin/phantom" --version', 'bin/phantom-mcp" --version']);
    const section = guide.split(`## ${platform}\n`)[1].split(`## ${next}\n`)[0];
    ordered(section, ["`umask`", "`mktemp -d`", "`TMPDIR`", "`/tmp`", "exit trap", "downloads", checksum, "`bash`", "`phantom --version`", "`phantom-mcp --version`", "attempts to remove the script", "empty staging directory", "not guaranteed", "not the install directory"]);
  }

  selected = "Windows";
  const card = find(QuickStart(), (element) => element.type === "article")[0];
  const command = find(card, (element) => typeof element.props.text === "string")[0].props.text;
  ordered(command, ["$ErrorActionPreference", "$Installer =", "$env:TEMP", "Invoke-WebRequest", "Get-FileHash", "if ($Actual -ne $Expected)", "& $Installer", "phantom.exe", "phantom-mcp.exe", "finally", "Remove-Item"]);
  const windows = guide.split("## Windows\n")[1].split("## Linux\n")[0];
  ordered(windows, ["stops on errors", "temporary", "$env:TEMP", "downloads", "Get-FileHash", "mismatch", "runs the verified installer", "versions", "`finally`", "remove", "not guaranteed"]);

  const steps = find(QuickStart(), (element) => typeof element.props.text === "string")
    .map((element) => element.props.text);
  ordered(steps.join("\n"), ["phantom --version\nphantom-mcp --version", "phantom init"]);
  ordered(guide.split("## After the platform command\n")[1], ["Verify both binaries", "`phantom --version`", "`phantom-mcp --version`", "Protect one supported project", "independent provider recovery copy", "supported HTTP API key", "`phantom init`", "illustrative"]);
});
