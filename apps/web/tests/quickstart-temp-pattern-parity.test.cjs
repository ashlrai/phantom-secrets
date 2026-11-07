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


const release = load("src/lib/public-release.ts");
function displayed(platform) {
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return { ...React, useState: () => [platform, () => {}] };
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return release;
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });
  return find(QuickStart(), (node) => typeof node.props.text === "string")[0].props.text.split("\n");
}

test("macOS and Linux examples share one temporary-directory creation pattern", () => {
  const macos = displayed("macOS");
  const linux = displayed("Linux");
  // Everything up to and including the cleanup trap is the staging setup.
  const setupEnd = (lines) => lines.findIndex((line) => line.startsWith("trap ")) + 1;
  assert.ok(setupEnd(macos) > 0);
  assert.deepEqual(macos.slice(0, setupEnd(macos)), linux.slice(0, setupEnd(linux)));
  const mktemps = [...macos, ...linux].filter((line) => line.includes("mktemp"));
  assert.equal(mktemps.length, 2);
  assert.equal(mktemps[0], mktemps[1]);
});

test("the shared staging setup creates a private directory and cleans it up", () => {
  const lines = displayed("Linux");
  const setup = lines.slice(0, lines.findIndex((line) => line.startsWith("trap ")) + 1);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom stage root "));
  try {
    const script = [...setup, 'printf "%s" "$phantom_stage"', ")"].join("\n").replace(/^\($/m, "(");
    // setup starts with "(" so the appended ")" closes the subshell.
    const result = spawnSync("bash", ["-c", script], { env: { PATH: process.env.PATH, TMPDIR: root }, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(result.stdout.startsWith(path.join(root, "phantom-install.")), result.stdout);
    assert.equal(fs.existsSync(result.stdout), false, "trap removed the empty staging directory");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
