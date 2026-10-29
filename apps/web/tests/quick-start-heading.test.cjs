const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

function load(relativePath, dependencies = {}) {
  const source = fs.readFileSync(path.join(__dirname, "..", relativePath), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, (name) => dependencies[name] ?? require(name));
  return exports;
}

test("rendered quick start is a named section with a clear heading hierarchy", () => {
  const release = load("src/lib/public-release.ts");
  for (const platform of ["macOS", "Windows", "Linux"]) {
    const { QuickStart } = load("src/components/landing/QuickStart.tsx", {
      react: { ...React, useState: () => [platform, () => {}] },
      "@/lib/public-release": release,
      "./CopyButton": { CopyButton: () => null },
      "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
    });
    const html = renderToStaticMarkup(React.createElement(QuickStart));

    const section = html.match(/^<section\b([^>]*)>([\s\S]*)<\/section>$/);
    assert.ok(section, "quick start renders a section");
    assert.match(section[1], /\bid="install"/);
    assert.doesNotMatch(section[1], /\b(?:hidden|aria-hidden="true")/);
    const label = section[1].match(/\baria-labelledby="([^"]+)"/);
    assert.ok(label, "the section is named by its heading");

    const headings = [...section[2].matchAll(/<h([1-6])\b([^>]*)>([\s\S]*?)<\/h\1>/g)];
    assert.deepEqual(headings.map((heading) => Number(heading[1])), [2, 3, 3, 3]);
    assert.match(headings[0][2], new RegExp(`\\bid="${label[1]}"`));
    assert.doesNotMatch(headings[0][2], /\b(?:hidden|aria-hidden="true")/);
    assert.equal(headings[0][3], "Install on your OS. Then protect one project.");
    assert.deepEqual(headings.slice(1).map((heading) => heading[3]), [
      platform, `Verify both ${release.PUBLIC_RELEASE_TAG} binaries`, "Protect one supported project",
    ]);
    assert.equal((html.match(new RegExp(`\\bid="${label[1]}"`, "g")) ?? []).length, 1, "heading ID is unique");
  }
});
