const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

function compile(file, extra = "", localRequire = require) {
  const source = fs.readFileSync(path.join(__dirname, "../src", file), "utf8") + extra;
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
    fileName: file,
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, localRequire);
  return exports;
}

const release = compile("lib/public-release.ts");
const { PLATFORMS } = compile("components/landing/QuickStart.tsx", "\nexport { PLATFORMS };", (name) => {
  if (name === "@/lib/public-release") return release;
  if (name === "./CopyButton" || name === "next/link") return {};
  return require(name);
});

function checkSyntax(executable, args, command) {
  const result = spawnSync(executable, args, { input: command, encoding: "utf8" });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

for (const name of ["macOS", "Linux"]) {
  test(`${name} install command parses as Bash without executing`, () => {
    const platform = PLATFORMS.find((item) => item.name === name);
    assert.ok(platform);
    checkSyntax("bash", ["-n"], platform.command);
  });
}

test("Windows install command parses as PowerShell without executing", () => {
  const platform = PLATFORMS.find((item) => item.name === "Windows");
  assert.ok(platform);
  const parser = [
    "$source = [Console]::In.ReadToEnd()",
    "$tokens = $null; $errors = $null",
    "$null = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)",
    "if ($errors.Count) { $errors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }; exit 1 }",
  ].join("; ");
  checkSyntax("pwsh", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", parser], platform.command);
});
