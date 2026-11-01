const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");

const root = path.join(__dirname, "../../..");
const review = fs.readFileSync(path.join(root, "docs/quickstart-platform-copy-review.md"), "utf8");

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

let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: (initial) => { assert.equal(initial, "macOS"); return [selected, () => {}]; } };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});

test("platform review matches the rendered commands, targets, prompts, and caveats", () => {
  assert.deepEqual(find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children),
    ["macOS", "Windows", "Linux"]);
  for (const [platform, script, digest, prompt, targets, caveat] of [
    ["macOS", "install.sh", "shasum -a 256 -c -", "$", ["Apple Silicon", "Intel"], "not notarized"],
    ["Windows", "install.ps1", "Get-FileHash -Algorithm SHA256", "PS>", ["ARM64", "x64"], "not Authenticode-signed"],
    ["Linux", "install.sh", "sha256sum -c -", "$", ["ARM64", "x64"], "session-persistent"],
  ]) {
    selected = platform;
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const copy = find(card, (node) => typeof node.props.text === "string")[0];
    const row = review.split("\n").find((line) => line.startsWith(`| ${platform} |`));
    assert.ok(row, `${platform}: review row`);
    for (const fragment of [script, digest, ...targets]) {
      assert.ok(row.includes(fragment), `${platform}: review missing ${fragment}`);
    }
    assert.ok(copy.props.text.includes(script));
    assert.ok(copy.props.text.includes(digest));
    assert.equal(copy.props.prompt, prompt);
    assert.ok(find(card, (node) => node.type === "p" && node.props.children?.includes(caveat)).length);
    for (const target of targets) {
      assert.equal(find(card, (node) => node.type === "a" && node.props["aria-label"]?.includes(target)).length, 2);
    }
  }
});

test("review covers shared steps and actionable copy checks", () => {
  const steps = find(QuickStart(), (node) => node.type === "ol")[0];
  assert.deepEqual(find(steps, (node) => typeof node.props.text === "string").map((node) => node.props.text),
    ["phantom --version\nphantom-mcp --version", "phantom init"]);
  for (const topic of ["Selection and copying", "Trust and order", "Temporary files", "Evidence and results", "Vault and recovery"]) {
    assert.match(review, new RegExp(`\\*\\*${topic}:\\*\\*[^]*?\\?`));
  }
  for (const phrase of ["`phantom --version`", "`phantom-mcp --version`", "`phantom init`", "illustrative", "`TMPDIR`", "`$env:TEMP`", "not guaranteed"]) {
    assert.ok(review.includes(phrase), `review missing ${phrase}`);
  }
  assert.doesNotMatch(review, /```|phm_[A-Za-z0-9]+/);
  assert.match(fs.readFileSync(path.join(root, "docs/README.md"), "utf8"), /\]\(quickstart-platform-copy-review\.md\)/);
});
