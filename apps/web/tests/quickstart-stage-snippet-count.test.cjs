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

test("staging snippet count and comparison match the displayed platform commands", () => {
  const docs = path.join(__dirname, "../../../docs");
  const guide = fs.readFileSync(path.join(docs, "quickstart-stage-snippet-count.md"), "utf8");
  const reference = fs.readFileSync(path.join(docs, "quickstart-temp-prefix-reference.md"), "utf8");
  let selected = "macOS";
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return { ...React, useState: () => [selected, () => {}] };
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });

  const platforms = find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children);
  assert.deepEqual(platforms, ["macOS", "Windows", "Linux"]);
  const staging = [];
  for (const platform of platforms) {
    selected = platform;
    const commands = find(QuickStart(), (node) => typeof node.props.text === "string");
    const lines = commands.flatMap((node) => node.props.text.split("\n").filter((line) => /\bmktemp\s+-d\b/.test(line)));
    const row = reference.split("\n").find((line) => line.startsWith(`| ${platform} |`));
    assert.ok(row, `${platform} reference row`);
    if (platform === "Windows") {
      assert.deepEqual(lines, []);
      assert.match(commands[0].props.text, /\$Installer = Join-Path \$env:TEMP \('phantom-install-[^']+-\{0\}\.ps1' -f \[Guid\]::NewGuid\(\)/);
      for (const fragment of ["No temporary directory", "`$env:TEMP`", "`phantom-install-`", "release tag", "GUID", "`.ps1`", "no fallback"]) {
        assert.ok(row.includes(fragment), `${platform} reference: ${fragment}`);
      }
    } else {
      assert.equal(lines.length, 1, platform);
      assert.equal(lines[0], 'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"');
      for (const fragment of ["`phantom-install.`", "`phantom-install.XXXXXX`", "`TMPDIR`", "`${TMPDIR:-/tmp}`", "`/tmp`", "unset or empty"]) {
        assert.ok(row.includes(fragment), `${platform} reference: ${fragment}`);
      }
      staging.push(lines[0]);
    }
  }
  assert.equal(staging.length, 2);
  assert.equal(staging[0], staging[1]);
  assert.ok(guide.includes(`\n${staging[0]}\n`));
  for (const fragment of ["**two**", "macOS", "Linux", "**match exactly**", "Windows", "`$env:TEMP`", "does not create a staging directory", "cleanup", "not guaranteed"]) {
    assert.ok(guide.includes(fragment), `guide: ${fragment}`);
  }
  assert.match(fs.readFileSync(path.join(docs, "README.md"), "utf8"), /\]\(quickstart-stage-snippet-count\.md\)/);
  assert.match(fs.readFileSync(path.join(docs, "README.md"), "utf8"), /\]\(quickstart-temp-prefix-reference\.md\)/);
});
