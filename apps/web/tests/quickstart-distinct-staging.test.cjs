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

let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: () => [selected, () => {}] };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});

for (const platform of ["macOS", "Linux"]) {
  test(`${platform} install command creates a distinct staging directory on each run`, (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "quickstart-distinct-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    selected = platform;
    const command = find(QuickStart(), (node) => typeof node.props.text === "string")[0].props.text;
    const lines = command.split("\n");
    const trap = lines.findIndex((line) => line.startsWith("trap "));
    assert.ok(trap > 0, "command installs a cleanup trap");
    const script = [...lines.slice(0, trap + 1), 'test -d "$phantom_stage"', 'printf "%s\\n" "$phantom_stage"', ")"].join("\n");
    const stages = Array.from({ length: 2 }, () => {
      const result = spawnSync("bash", ["-c", script], {
        env: { PATH: "/usr/bin:/bin", HOME: root, TMPDIR: root }, encoding: "utf8", timeout: 30000,
      });
      assert.equal(result.status, 0, result.stderr);
      const stage = result.stdout.trim();
      assert.equal(path.dirname(stage), root);
      assert.equal(fs.existsSync(stage), false, "cleanup removes the staging directory");
      return stage;
    });
    assert.notEqual(stages[0], stages[1]);
  });
}
