const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const React = require("react");
const ts = require("typescript");
const Parser = require("tree-sitter");

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

function bashSyntax(command) {
  const result = spawnSync("bash", ["-n"], { input: command, encoding: "utf8" });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
}

async function powershellSyntax(command) {
  const parser = new Parser();
  parser.setLanguage((await import("tree-sitter-powershell")).default);
  const tree = parser.parse(command);
  assert.equal(tree.rootNode.hasError, false, tree.rootNode.toString());
}

test("every displayed Quick Start command parses in its shell without executing", async () => {
  const platforms = find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children);
  assert.deepEqual(platforms, ["macOS", "Windows", "Linux"]);
  for (const platform of platforms) {
    selected = platform;
    const commands = find(QuickStart(), (node) => typeof node.props.text === "string");
    assert.equal(commands.length, 3, `${platform} command count`);
    for (const [index, command] of commands.entries()) {
      const prompt = command.props.prompt ?? "$";
      assert.ok(prompt === "$" || prompt === "PS>", `${platform} command ${index + 1}: unknown shell prompt`);
      const check = prompt === "PS>" ? powershellSyntax : bashSyntax;
      await assert.doesNotReject(async () => check(command.props.text), `${platform} command ${index + 1}`);
    }
  }
});

test("syntax checks reject malformed Bash and PowerShell", async () => {
  assert.throws(() => bashSyntax("if true; then\n"));
  await assert.rejects(() => powershellSyntax("try { Write-Host 'hello'"));
});
