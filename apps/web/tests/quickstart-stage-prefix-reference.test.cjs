const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");

const root = path.join(__dirname, "../../..");

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

test("staging reference matches both rendered Unix commands", () => {
  const doc = fs.readFileSync(path.join(root, "docs/quickstart-stage-prefix-reference.md"), "utf8");
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
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const command = find(card, (node) => typeof node.props.text === "string")[0].props.text;
    const section = doc.split(`## ${platform}\n`)[1]?.split(/\n## /)[0];
    assert.ok(section, `${platform}: reference section`);
    const stage = command.match(/^phantom_stage="\$\(mktemp -d "([^"\n]+)"\)"$/m);
    assert.ok(stage, `${platform}: quoted mktemp staging template`);
    assert.equal(stage[1], "${TMPDIR:-/tmp}/phantom-install.XXXXXX");
    assert.ok(section.includes(`\`${stage[1]}\``), `${platform}: documented template`);
    assert.match(section, /`phantom-install\.`/);
    assert.match(section, /`TMPDIR` when set and nonempty/);
    assert.match(section, /`\/tmp` when `TMPDIR` is unset or empty/);
    assert.match(section, /`install\.sh`/);
    assert.ok(command.includes('phantom_installer="$phantom_stage/install.sh"'));
  }
  assert.match(doc, /cleanup is best\s+effort/);
  assert.match(fs.readFileSync(path.join(root, "docs/README.md"), "utf8"), /\]\(quickstart-stage-prefix-reference\.md\)/);
});
