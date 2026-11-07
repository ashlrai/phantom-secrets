const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");

const root = path.join(__dirname, "../../..");
const doc = fs.readFileSync(path.join(root, "docs/quickstart-platform-step-map.md"), "utf8");
const source = fs.readFileSync(path.join(root, "apps/web/src/components/landing/QuickStart.tsx"), "utf8");

function load(file, localRequire = require) {
  const input = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
  const compiled = ts.transpileModule(input, {
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

let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: () => [selected, () => {}] };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});

test("step map follows each rendered platform command and architecture", () => {
  assert.deepEqual(find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children),
    ["macOS", "Windows", "Linux"]);
  for (const [platform, commandStages, mapStages, architectures] of [
    ["macOS", ["mktemp -d", "trap ", "curl ", "shasum -a 256 -c -", 'bash "$phantom_installer"', 'bin/phantom" --version', 'bin/phantom-mcp" --version'], ["`mktemp -d`", "exit trap", "downloads `install.sh`", "`shasum -a 256 -c -`", "`bash`", "versions", "trap attempts"], ["Apple Silicon", "Intel"]],
    ["Windows", ["$env:TEMP", "Invoke-WebRequest", "Get-FileHash -Algorithm SHA256", "if ($Actual -ne $Expected)", "& $Installer", "phantom.exe", "phantom-mcp.exe", "finally", "Remove-Item"], ["`$env:TEMP`", "downloads `install.ps1`", "`Get-FileHash -Algorithm SHA256`", "mismatch stops execution", "versions", "`finally` attempts"], ["ARM64", "x64"]],
    ["Linux", ["mktemp -d", "trap ", "curl ", "sha256sum -c -", 'bash "$phantom_installer"', 'bin/phantom" --version', 'bin/phantom-mcp" --version'], ["`mktemp -d`", "exit trap", "downloads `install.sh`", "`sha256sum -c -`", "`bash`", "versions", "trap attempts"], ["ARM64", "x64"]],
  ]) {
    selected = platform;
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const command = find(card, (node) => typeof node.props.text === "string")[0].props.text;
    const row = doc.split("\n").find((line) => line.startsWith(`| [${platform}]`));
    assert.ok(row, `${platform}: map row`);
    ordered(command, commandStages);
    ordered(row, mapStages);
    for (const architecture of architectures) {
      assert.ok(row.includes(architecture), `${platform}: map includes ${architecture}`);
      assert.ok(find(card, (node) => node.type === "a" && node.props["aria-label"]?.includes(architecture)).length >= 2,
        `${platform}: archive and checksum links for ${architecture}`);
    }
  }
});

test("shared steps and source citations stay aligned with the component", () => {
  const view = QuickStart();
  const steps = find(view, (node) => node.type === "ol")[0];
  assert.deepEqual(find(steps, (node) => typeof node.props.text === "string").map((node) => node.props.text),
    ["phantom --version\nphantom-mcp --version", "phantom init"]);
  const headings = find(steps, (node) => node.type === "h3").map((node) => node.props.children);
  assert.match(headings[0], /^Verify both .+ binaries$/);
  assert.equal(headings[1], "Protect one supported project");
  ordered(doc.split("## Shared numbered steps\n")[1], ["Verify both binaries", "`phantom --version`", "`phantom-mcp --version`", "Protect one supported project", "independent provider recovery copy", "supported HTTP API key", "`phantom init`", "illustrative"]);

  const lines = source.split("\n");
  for (const [range, marker] of [["130-L199", "PLATFORMS.filter"], ["40-L66", 'name: "macOS"'], ["67-L100", 'name: "Windows"'], ["101-L127", 'name: "Linux"'], ["201-L221", "platform-install-note"], ["15-L28", "const STEPS"], ["224-L241", "STEPS.map"]]) {
    assert.ok(doc.includes(`QuickStart.tsx#L${range}`), `missing source citation ${range}`);
    const [start, end] = range.split("-L").map(Number);
    assert.ok(lines.slice(start - 1, end).join("\n").includes(marker), `stale source citation ${range}`);
  }
  assert.match(fs.readFileSync(path.join(root, "docs/README.md"), "utf8"), /\]\(quickstart-platform-step-map\.md\)/);
});
