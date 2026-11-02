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

const docs = path.join(__dirname, "../../../docs");
const guide = fs.readFileSync(path.join(docs, "quickstart-staging-copy-check.md"), "utf8");
let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: () => [selected, () => {}] };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});

// Every copyable text displayed for a platform selection: the card command
// plus the shared step commands, so a stray staging occurrence anywhere in
// the rendered panel is counted.
function displayed(platform) {
  selected = platform;
  return find(QuickStart(), (node) => typeof node.props.text === "string")
    .map((node) => node.props.text);
}

function stagingCommands(platform) {
  return displayed(platform).filter((text) => /\bmktemp\s+-d\b/.test(text));
}

test("the staging command is displayed in exactly the two documented occurrences", () => {
  assert.deepEqual(
    find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children),
    ["macOS", "Windows", "Linux"],
  );
  assert.equal(stagingCommands("macOS").length, 1, "macOS occurrence");
  assert.equal(stagingCommands("Linux").length, 1, "Linux occurrence");
  assert.deepEqual(stagingCommands("Windows"), [], "Windows displays no staging command");
  assert.doesNotMatch(displayed("Windows").join("\n"), /mktemp/);

  // The guide identifies both occurrences and the Windows difference.
  for (const fragment of ["**two**", "occurrences", "macOS", "Linux",
    "`command` array", "`PLATFORMS`", "copy control", "Windows", "`$env:TEMP`",
    "no `mktemp`"]) {
    assert.ok(guide.includes(fragment), `guide identifies: ${fragment}`);
  }
});

test("the documented check holds: both occurrences match except the checksum line", () => {
  const [macos] = stagingCommands("macOS");
  const [linux] = stagingCommands("Linux");
  const macosLines = macos.split("\n");
  const linuxLines = linux.split("\n");
  assert.equal(macosLines.length, 12, "twelve-line subshell as documented");
  assert.equal(macosLines.length, linuxLines.length);

  const differing = macosLines.filter((line, index) => line !== linuxLines[index]);
  assert.equal(differing.length, 1, "exactly one platform-specific line");
  assert.match(differing[0], /\| shasum -a 256 -c -$/);
  assert.match(linuxLines[macosLines.indexOf(differing[0])], /\| sha256sum -c -$/);

  // The guide describes the check, its one allowed difference, and its
  // failure modes in terms that match the displayed commands.
  for (const fragment of ["line by line", "Exactly one line", "byte for byte",
    "`shasum -a 256 -c -`", "`sha256sum -c -`", "twelve-line", "shared verbatim",
    "drift"]) {
    assert.ok(guide.includes(fragment), `guide describes: ${fragment}`);
  }
});

test("the guide is discoverable and names its automated check", () => {
  assert.match(fs.readFileSync(path.join(docs, "README.md"), "utf8"),
    /\]\(quickstart-staging-copy-check\.md\)/);
  assert.ok(guide.includes("node --test tests/quickstart-staging-copy-check.test.cjs"));
  for (const link of [
    "../apps/web/src/components/landing/QuickStart.tsx",
    "../apps/web/src/lib/public-release.ts",
    "quickstart-staging-comparison.md",
    "quickstart-stage-snippet-count.md",
  ]) {
    assert.ok(guide.includes(`](${link})`), `missing link to ${link}`);
    assert.ok(fs.existsSync(path.resolve(docs, link.split("#")[0])), `missing target ${link}`);
  }
});
