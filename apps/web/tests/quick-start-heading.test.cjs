const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { JSDOM } = require("jsdom");

function load(relativePath, dependencies = {}) {
  const source = fs.readFileSync(path.join(__dirname, "..", relativePath), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, (name) => dependencies[name] ?? require(name));
  return exports;
}

test("initial QuickStart render displays the six-X mktemp staging template", () => {
  const icons = load("src/components/landing/Icons.tsx");
  const copyButton = load("src/components/landing/CopyButton.tsx", {
    "./Icons": icons,
    "@/lib/posthog": { capturePostHog: async () => {} },
  });
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", {
    "@/lib/public-release": load("src/lib/public-release.ts"),
    "./CopyButton": copyButton,
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
  });
  const html = renderToStaticMarkup(React.createElement(QuickStart));
  const dom = new JSDOM(html);
  try {
    const command = dom.window.document.querySelector(".platform-install-card__command .copy-command > span:first-child");
    assert.ok(command, "the initial platform install command is displayed");
    const stagingLines = command.textContent.split("\n").filter((line) => line.includes("mktemp"));
    assert.deepEqual(stagingLines, [
      'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"',
    ]);
  } finally {
    dom.window.close();
  }
});

test("rendered quick start is a named section with a clear heading hierarchy", () => {
  const release = load("src/lib/public-release.ts");
  let selectedPlatform = "macOS";
  const hooks = { ...React, useState: () => [selectedPlatform, () => {}] };
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", {
    "@/lib/public-release": release,
    react: hooks,
    "./CopyButton": { CopyButton: () => null },
    "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
  });
  for (const platform of ["macOS", "Windows", "Linux"]) {
    selectedPlatform = platform;
    const html = renderToStaticMarkup(React.createElement(QuickStart));
    const section = html.match(/^<section\b([^>]*)>([\s\S]*)<\/section>$/);
    assert.ok(section, `${platform}: quick start renders a section`);
    assert.match(section[1], /\bid="install"/);
    assert.doesNotMatch(section[1], /\b(?:hidden|aria-hidden="true")/);
    const label = section[1].match(/\baria-labelledby="([^"]+)"/);
    assert.ok(label, `${platform}: the section is named by its heading`);

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
