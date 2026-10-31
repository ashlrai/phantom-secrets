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

test("platform comparison tracks the displayed cards and their temporary staging", () => {
  const guide = fs.readFileSync(path.join(__dirname, "../../../docs/quickstart-platform-comparison.md"), "utf8");
  let selected = "macOS";
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return { ...React, useState: () => [selected, () => {}] };
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });

  assert.deepEqual(find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children),
    ["macOS", "Windows", "Linux"]);
  for (const [platform, digest] of [["macOS", "shasum -a 256 -c -"], ["Windows", "Get-FileHash -Algorithm SHA256"], ["Linux", "sha256sum -c -"]]) {
    selected = platform;
    const card = find(QuickStart(), (node) => node.type === "article")[0];
    const command = find(card, (node) => typeof node.props.text === "string")[0].props.text;
    assert.ok(command.includes(digest), `${platform} command digest check`);
    assert.ok(guide.includes(digest), `${platform} guide digest check`);
    const archives = find(card, (node) => node.type === "a" && /\.(?:zip|tar\.gz)$/.test(node.props.href));
    assert.equal(archives.length, 2, `${platform} archive links`);
    for (const archive of archives) assert.ok(guide.includes(archive.props.href.split("/").pop()));
    for (const fragment of platform === "Windows"
      ? ["$env:TEMP", "finally", "Remove-Item"]
      : ["umask 077", "mktemp -d", "TMPDIR", "trap ", "rmdir "]) {
      assert.ok(command.includes(fragment), `${platform} command: ${fragment}`);
    }
  }
  for (const fragment of ["`TMPDIR`", "`/tmp`", "`$env:TEMP`", "`finally`", "not guaranteed", "not the install directory", "`phantom --version`", "`phantom-mcp --version`"]) {
    assert.ok(guide.includes(fragment), `guide: ${fragment}`);
  }
  assert.doesNotMatch(guide, /phantom init|phantom (?:add|remove|rotate|sync)\b/i);
  assert.match(fs.readFileSync(path.join(__dirname, "../../../docs/README.md"), "utf8"), /\]\(quickstart-platform-comparison\.md\)/);
});
