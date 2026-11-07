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

let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: () => [selected, () => {}] };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});

function installSnippet(platform) {
  selected = platform;
  return find(QuickStart(), (node) => typeof node.props.text === "string")[0].props.text;
}

for (const platform of ["macOS", "Linux"]) {
  test(`${platform} install snippet stages under the TMPDIR fallback with the phantom-install prefix`, () => {
    const lines = installSnippet(platform).split("\n");
    const staging = lines.filter((line) => line.startsWith("phantom_stage="));
    assert.deepEqual(staging, ['phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"']);
    // The staging directory must exist before the installer path derived from it is used.
    assert.ok(lines.indexOf(staging[0]) < lines.findIndex((line) => line.startsWith("phantom_installer=")));
  });
}

test("macOS and Linux snippets share the same staging line; Windows has none", () => {
  const stage = (platform) => installSnippet(platform).split("\n").find((line) => line.startsWith("phantom_stage="));
  assert.ok(stage("macOS"));
  assert.equal(stage("macOS"), stage("Linux"));
  assert.doesNotMatch(installSnippet("Windows"), /TMPDIR|mktemp/);
});
