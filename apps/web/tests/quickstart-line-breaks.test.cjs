const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { JSDOM } = require("jsdom");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

function load(file, dependencies = {}) {
  const source = fs.readFileSync(path.join(__dirname, "../src", file), "utf8");
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", compiled)(exports, (name) => dependencies[name] ?? require(name));
  return exports;
}

test("install commands retain their line boundaries when rendered", () => {
  let selected = "macOS";
  const copy = load("components/landing/CopyButton.tsx", {
    "./Icons": load("components/landing/Icons.tsx"),
    "@/lib/posthog": { capturePostHog: async () => {} },
  });
  const { QuickStart } = load("components/landing/QuickStart.tsx", {
    react: { ...React, useState: () => [selected, () => {}] },
    "./CopyButton": copy,
    "@/lib/public-release": load("lib/public-release.ts"),
    "next/link": { __esModule: true, default: "a" },
  });
  const css = fs.readFileSync(path.join(__dirname, "../src/app/globals.css"), "utf8");

  for (const [platform, first, second, last] of [
    ["macOS", "(", "set -euo pipefail", ")"],
    ["Windows", "& {", "$ErrorActionPreference = 'Stop'", "}"],
    ["Linux", "(", "set -euo pipefail", ")"],
  ]) {
    selected = platform;
    const html = renderToStaticMarkup(React.createElement(QuickStart));
    const dom = new JSDOM(`<!doctype html><style>${css}</style>${html}`, { url: "http://localhost/" });
    try {
      const text = dom.window.document.querySelector(".platform-install-card__command .copy-command > span:first-child");
      assert.ok(text, `${platform}: command is displayed`);
      const command = Array.from(text.childNodes)
        .filter((node) => node.nodeType === dom.window.Node.TEXT_NODE)
        .map((node) => node.textContent).join("");
      const lines = command.split("\n");
      assert.ok(lines.length > 3, `${platform}: command has multiple lines`);
      assert.deepEqual(lines.slice(0, 2), [first, second], `${platform}: first commands occupy separate lines`);
      assert.equal(lines.at(-1), last, `${platform}: closing delimiter has its own line`);
      assert.equal(dom.window.getComputedStyle(text).whiteSpace, "pre-wrap", `${platform}: line breaks are visible`);
    } finally {
      dom.window.close();
    }
  }
});
