const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

function load(relativePath, localRequire = require) {
  const source = fs.readFileSync(path.join(__dirname, "..", relativePath), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, localRequire);
  return exports;
}

function findElements(element, predicate) {
  if (!React.isValidElement(element)) return [];
  return [
    ...(predicate(element) ? [element] : []),
    ...React.Children.toArray(element.props.children).flatMap((child) => findElements(child, predicate)),
  ];
}

test("switching platforms displays the selected install instructions", () => {
  let selected;
  const hooks = { ...React, useState(initial) { selected ??= initial; return [selected, (value) => { selected = value; }]; } };
  const release = load("src/lib/public-release.ts");
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return hooks;
    if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
    if (name === "@/lib/public-release") return release;
    if (name === "./CopyButton") return { CopyButton: ({ text }) => React.createElement("pre", null, text) };
    return require(name);
  });

  const cases = [
    { name: "macOS", command: "shasum -a 256 -c -", asset: "phantom-aarch64-apple-darwin.tar.gz", caveat: "The release is not notarized" },
    { name: "Windows", command: "Get-FileHash -Algorithm SHA256", asset: "phantom-aarch64-pc-windows-msvc.zip", caveat: "Windows archives are not Authenticode-signed" },
    { name: "Linux", command: "sha256sum -c -", asset: "phantom-aarch64-unknown-linux-gnu.tar.gz", caveat: "The default keyutils vault is session-persistent" },
    { name: "macOS", command: "shasum -a 256 -c -", asset: "phantom-aarch64-apple-darwin.tar.gz", caveat: "The release is not notarized" },
  ];

  for (const [index, expected] of cases.entries()) {
    if (index > 0) {
      const buttons = findElements(QuickStart(), (element) => element.type === "button");
      const button = buttons.find((element) => element.props.children === expected.name);
      assert.ok(button, `selector for ${expected.name}`);
      button.props.onClick();
    }
    const tree = QuickStart();
    const buttons = findElements(tree, (element) => element.type === "button");
    assert.equal(buttons.length, 3);
    for (const button of buttons) assert.equal(button.props["aria-pressed"], button.props.children === expected.name);
    const html = renderToStaticMarkup(tree);
    assert.match(html, new RegExp(`<h3>${expected.name}</h3>`));
    for (const other of cases.filter((item) => item.name !== expected.name)) {
      assert.ok(!html.includes(`<h3>${other.name}</h3>`));
      assert.ok(!html.includes(other.asset));
    }
    for (const content of [expected.command, expected.asset, expected.caveat]) assert.ok(html.includes(content), content);
  }
});
