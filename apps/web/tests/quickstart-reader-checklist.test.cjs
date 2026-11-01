const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const React = require("react");
const ts = require("typescript");

const root = path.join(__dirname, "../../..");
const checklist = fs.readFileSync(path.join(root, "docs/quickstart-reader-checklist.md"), "utf8");

function load(file, localRequire = require) {
  const source = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", compiled)(exports, localRequire);
  return exports;
}

function find(node, predicate) {
  if (!React.isValidElement(node)) return [];
  return [
    ...(predicate(node) ? [node] : []),
    ...React.Children.toArray(node.props.children).flatMap((child) => find(child, predicate)),
  ];
}

let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: (initial) => { assert.equal(initial, "macOS"); return [selected, () => {}]; } };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});

test("reader checklist tracks the selector, architecture labels and prompts", () => {
  const buttons = find(QuickStart(), (node) => node.type === "button");
  assert.deepEqual(buttons.map((node) => node.props.children), ["macOS", "Windows", "Linux"]);
  for (const [platform, labels, prompt] of [
    ["macOS", ["Apple Silicon", "Intel"], "$"],
    ["Windows", ["ARM64", "x64"], "PS>"],
    ["Linux", ["ARM64", "x64"], "$"],
  ]) {
    selected = platform;
    const tree = QuickStart();
    const card = find(tree, (node) => node.type === "article")[0];
    assert.equal(find(card, (node) => node.type === "h3")[0].props.children, platform);
    assert.equal(find(tree, (node) => node.type === "button" && node.props["aria-pressed"])[0].props.children, platform);
    for (const label of labels) {
      assert.ok(checklist.includes(label));
      const links = find(card, (node) => node.type === "a" && node.props["aria-label"]?.includes(`${platform} ${label}`));
      assert.equal(links.length, 2, `${platform} ${label}: archive and checksum`);
      assert.ok(links.some((link) => link.props.href.endsWith(".sha256")));
    }
    const copy = find(card, (node) => typeof node.props.text === "string")[0];
    assert.equal(copy.props.prompt || "$", prompt);
    assert.ok(checklist.includes(`\`${prompt}\``));
  }
  assert.match(fs.readFileSync(path.join(root, "docs/README.md"), "utf8"), /\]\(quickstart-reader-checklist\.md\)/);
});

test("reader checklist describes each command's verification and cleanup boundaries", () => {
  for (const [platform, checksum, execute, cleanup] of [
    ["macOS", "shasum -a 256 -c -", 'bash "$phantom_installer"', 'trap \'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage"'],
    ["Windows", "Get-FileHash -Algorithm SHA256", "& $Installer", "Remove-Item -LiteralPath $Installer"],
    ["Linux", "sha256sum -c -", 'bash "$phantom_installer"', 'trap \'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage"'],
  ]) {
    selected = platform;
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const command = find(card, (node) => typeof node.props.text === "string")[0].props.text;
    assert.ok(command.includes(checksum) && checklist.includes(`\`${checksum}\``));
    assert.ok(command.indexOf(checksum) < command.indexOf(execute), `${platform}: verify before execution`);
    assert.ok(command.includes(cleanup), `${platform}: cleanup`);
  }
  for (const phrase of ["unset or empty", "after the trap is installed", "`$env:TEMP`", "`finally`",
    "best effort, not guaranteed", "another install may", "keyboard", "narrow widths", "Receipts are illustrative"]) {
    assert.ok(checklist.includes(phrase), phrase);
  }
});
