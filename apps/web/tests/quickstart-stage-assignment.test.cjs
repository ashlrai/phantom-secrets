const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
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

test("Unix Quick Start assignments create a nonempty staging path", (t) => {
  let selected = "macOS";
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return { ...React, useState: () => [selected, () => {}] };
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "quickstart-assignment-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const parent = path.join(root, "writable temp parent");
  fs.mkdirSync(parent);

  for (const platform of ["macOS", "Linux"]) {
    selected = platform;
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const command = find(card, (node) => typeof node.props.text === "string")[0].props.text;
    const assignment = command.split("\n").find((line) => line.startsWith("phantom_stage="));
    assert.ok(assignment, `${platform}: staging assignment exists`);
    const result = spawnSync("/bin/bash", ["-c", `set -eu\n${assignment}\nprintf '%s' "$phantom_stage"`], {
      env: { HOME: root, PATH: "/usr/bin:/bin", TMPDIR: parent },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, `${platform}: ${result.stderr}`);
    assert.notEqual(result.stdout, "", `${platform}: staging path is nonempty`);
    assert.equal(path.dirname(result.stdout), parent, `${platform}: staging path is under the temporary parent`);
    assert.ok(fs.statSync(result.stdout).isDirectory(), `${platform}: staging path exists`);
  }
});
