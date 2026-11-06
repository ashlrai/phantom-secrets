const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");

const root = path.join(__dirname, "../../..");
const review = fs.readFileSync(path.join(root, "docs/quickstart-copy-review.md"), "utf8");

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

test("copy review describes the rendered platform choices and shared steps", () => {
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
    assert.ok(review.includes(platform), `review includes ${platform}`);
    selected = platform;
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const links = find(card, (node) => node.type === "a");
    assert.equal(links.filter((node) => node.props["aria-label"]?.startsWith("Download Phantom ")).length, 2);
    assert.equal(links.filter((node) => node.props["aria-label"]?.startsWith("Download the SHA-256 checksum")).length, 2);
    assert.equal(find(card, (node) => typeof node.props.text === "string").length, 1);
  }
  const steps = find(QuickStart(), (node) => node.type === "ol")[0];
  assert.deepEqual(find(steps, (node) => typeof node.props.text === "string").map((node) => node.props.text),
    ["phantom --version\nphantom-mcp --version", "phantom init"]);
  assert.match(review, /installed-path checks[\s\S]*independent provider recovery copy[\s\S]*`phantom init`[\s\S]*illustrative/);
});

test("review raises actionable questions and is discoverable without copying command blocks", () => {
  const questions = review.split("## Questions for copy review\n")[1];
  assert.ok(questions);
  for (const topic of ["Starting point", "Download choice", "Trust and policy", "Version checks", "First project", "Vault choice", "Result and cleanup"]) {
    assert.match(questions, new RegExp(`\\*\\*${topic}:\\*\\*[^]*?\\?`));
  }
  assert.doesNotMatch(review, /```|phm_[A-Za-z0-9]+/);
  assert.match(fs.readFileSync(path.join(root, "docs/README.md"), "utf8"), /\]\(quickstart-copy-review\.md\)/);
});
