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

// Each displayed Unix snippet must capture its mktemp result in phantom_stage,
// so the trap and installer path name the directory that was actually created.
test("every displayed Unix snippet assigns the mktemp result to phantom_stage", () => {
  let selected = "macOS";
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return { ...React, useState: () => [selected, () => {}] };
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });

  for (const platform of ["macOS", "Linux"]) {
    selected = platform;
    const [install] = find(QuickStart(), (node) => typeof node.props.text === "string");
    const lines = install.props.text.split("\n");
    const mktemp = lines.filter((line) => /\bmktemp\b/.test(line));
    assert.equal(mktemp.length, 1, `${platform}: exactly one mktemp call`);
    assert.match(mktemp[0], /^phantom_stage="\$\(mktemp -d "\$\{TMPDIR:-\/tmp\}\/phantom-install\.XXXXXX"\)"$/, platform);
    assert.ok(lines.includes('phantom_installer="$phantom_stage/install.sh"'), `${platform}: installer lives in phantom_stage`);
  }
});
