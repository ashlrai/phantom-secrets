const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");

const root = path.join(__dirname, "../../..");
const guide = fs.readFileSync(path.join(root, "docs/quickstart-content-maintenance.md"), "utf8");

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

test("maintenance checklist follows each rendered platform and command", () => {
  let selected = "macOS";
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return { ...React, useState: (initial) => { assert.equal(initial, "macOS"); return [selected, () => {}]; } };
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });

  const choices = find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children);
  assert.deepEqual(choices, ["macOS", "Windows", "Linux"]);
  for (const platform of choices) {
    assert.ok(guide.includes(platform), `checklist names ${platform}`);
    selected = platform;
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const command = find(card, (node) => typeof node.props.text === "string")[0].props.text;
    if (platform === "Windows") {
      ordered(command, ["try {", "Invoke-WebRequest", "Get-FileHash", "& $Installer", "phantom.exe", "phantom-mcp.exe", "finally", "Remove-Item"]);
    } else {
      ordered(command, ["mktemp -d", "trap '", "rm -f", "rmdir", "curl ", platform === "macOS" ? "shasum -a 256 -c -" : "sha256sum -c -", 'bash "$phantom_installer"', 'bin/phantom" --version', 'bin/phantom-mcp" --version']);
    }
  }
  const steps = find(QuickStart(), (node) => node.type === "ol")[0];
  assert.deepEqual(find(steps, (node) => typeof node.props.text === "string").map((node) => node.props.text),
    ["phantom --version\nphantom-mcp --version", "phantom init"]);
  ordered(guide, ["**Platform labels:**", "**Displayed command order:**", "`phantom --version`", "`phantom-mcp --version`", "`phantom init`", "**Cleanup wording:**", "`EXIT` trap", "`finally`", "Cleanup is not guaranteed"]);
  assert.match(guide, /empty staging directory/);
  assert.match(guide, /temporary\s+installer file/);
});

test("maintenance checklist is discoverable and points to review evidence", () => {
  for (const link of ["../apps/web/src/components/landing/QuickStart.tsx", "../apps/web/src/lib/public-release.ts", "quickstart-platform-step-map.md", "quickstart-command-sequence.md", "quickstart-temp-cleanup-review.md", "getting-started.md#exact-github-assets-macos-linux-and-windows"]) {
    assert.ok(guide.includes(`](${link})`), `missing link to ${link}`);
    assert.ok(fs.existsSync(path.resolve(root, "docs", link.split("#")[0])), `missing target ${link}`);
  }
  assert.match(guide, /- \[ \] \*\*Verify:\*\*/);
  assert.doesNotMatch(guide, /```|phm_[A-Za-z0-9]+/);
  assert.match(fs.readFileSync(path.join(root, "docs/README.md"), "utf8"), /\]\(quickstart-content-maintenance\.md\)/);
});
