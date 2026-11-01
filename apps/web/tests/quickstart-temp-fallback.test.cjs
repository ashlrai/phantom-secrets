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

test("both documented staging assignments match the displayed commands and their fallback behavior", (t) => {
  const root = path.join(__dirname, "../../..");
  const guide = fs.readFileSync(path.join(root, "docs/quickstart-temp-fallback.md"), "utf8");
  let selected = "macOS";
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return { ...React, useState: () => [selected, () => {}] };
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-fallback-test-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const spacedParent = path.join(tempRoot, "parent with spaces");
  fs.mkdirSync(spacedParent);

  for (const platform of ["macOS", "Linux"]) {
    selected = platform;
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const command = find(card, (node) => typeof node.props.text === "string")[0].props.text;
    const assignment = command.split("\n").find((line) => line.startsWith("phantom_stage="));
    const section = guide.split(`## ${platform}\n`)[1]?.split("\n## ")[0];
    assert.ok(section, `${platform} section`);
    assert.ok(section.includes(`\n${assignment}\n`), `${platform} documented assignment`);
    for (const term of ["`TMPDIR`", "`/tmp`", "unset or empty", "`phantom-install.`"]) {
      assert.ok(section.includes(term), `${platform} documentation: ${term}`);
    }
    assert.equal(assignment, 'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"');

    for (const [label, value, expected] of [
      ["unset", undefined, "/tmp"],
      ["empty", "", "/tmp"],
      ["spaces", spacedParent, spacedParent],
      ["missing parent", path.join(tempRoot, "missing"), null],
    ]) {
      const env = { PATH: "/usr/bin:/bin", HOME: process.env.HOME, EXPECTED_PARENT: expected || "" };
      if (value !== undefined) env.TMPDIR = value;
      const script = `set -eu\n${assignment}\ntrap 'rmdir -- "$phantom_stage"' EXIT\ncase "$phantom_stage" in "$EXPECTED_PARENT"/phantom-install.??????) test -d "$phantom_stage" ;; *) exit 1 ;; esac`;
      const result = spawnSync("bash", ["-c", script], { env, encoding: "utf8" });
      assert.equal(result.status, expected === null ? 1 : 0, `${platform}: ${label}`);
    }
  }
  assert.match(fs.readFileSync(path.join(root, "docs/README.md"), "utf8"), /\]\(quickstart-temp-fallback\.md\)/);
});
