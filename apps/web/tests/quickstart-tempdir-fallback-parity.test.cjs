const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const React = require("react");
const ts = require("typescript");

// Offline parity check for the two generated Unix installer commands
// (macOS and Linux). Both variants are built from separate literals in
// QuickStart.tsx, so this test pins that they share one TMPDIR fallback
// instead of drifting apart.

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

const release = load("src/lib/public-release.ts");
function displayedCommand(platform) {
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return { ...React, useState: () => [platform, () => {}] };
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return release;
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });
  const card = find(QuickStart(), (node) => node.type === "article")[0];
  return find(card, (node) => typeof node.props.text === "string")[0].props.text;
}

// The TMPDIR fallback expression inside the mktemp template, e.g.
// "${TMPDIR:-/tmp}". Both variants must produce the identical string.
function tmpdirFallback(command) {
  const match = command.match(/mktemp -d "([^"]+)"/);
  assert.ok(match, "command stages with a quoted mktemp template");
  const fallback = match[1].match(/\$\{TMPDIR[^}]*\}/);
  assert.ok(fallback, "mktemp template carries a TMPDIR fallback");
  return fallback[0];
}

const variants = ["macOS", "Linux"];

test("both generated installer commands use the same TMPDIR fallback", () => {
  const fallbacks = variants.map((platform) => {
    const command = displayedCommand(platform);
    const staging = command.split("\n").filter((line) => /\bmktemp\b/.test(line));
    assert.equal(staging.length, 1, `${platform}: exactly one staging line`);
    return { platform, fallback: tmpdirFallback(command), staging: staging[0] };
  });

  // One shared fallback expression: the colon form treats unset and empty
  // TMPDIR alike and defaults to /tmp for both variants.
  assert.equal(fallbacks[0].fallback, fallbacks[1].fallback, "macOS and Linux share one TMPDIR fallback");
  assert.equal(fallbacks[0].fallback, "${TMPDIR:-/tmp}");

  // The whole staging setup through the EXIT trap is identical between the
  // two variants, so the fallback cannot drift in either command.
  const setupThroughTrap = (command) => {
    const lines = command.split("\n");
    return lines.slice(0, lines.findIndex((line) => line.startsWith("trap ")) + 1).join("\n");
  };
  const setups = variants.map((platform) => setupThroughTrap(displayedCommand(platform)));
  assert.equal(setups[0], setups[1], "macOS and Linux share the same staging setup");
});

test("both variants honor the shared fallback when TMPDIR is unset or empty", (t) => {
  for (const platform of variants) {
    for (const [label, value] of [["unset", undefined], ["empty", ""]]) {
      const command = displayedCommand(platform);
      const lines = command.split("\n");
      const trap = lines.findIndex((line) => line.startsWith("trap "));
      assert.ok(trap > 0, `${platform}: displayed command installs an EXIT trap`);
      // Keep the real staging prologue; replace download/install steps with a
      // fixture write so nothing touches the network.
      const script = [
        ...lines.slice(0, trap + 1),
        'printf "%s\\n" "$phantom_stage"',
        'printf fixture > "$phantom_installer"',
        ")",
      ].join("\n");

      const env = { ...process.env };
      if (value === undefined) delete env.TMPDIR;
      else env.TMPDIR = value;
      const result = spawnSync("bash", ["-c", script], { env, encoding: "utf8" });
      assert.equal(result.status, 0, `${platform} ${label}: ${result.stderr}`);
      const stage = result.stdout.trim();
      assert.match(
        stage,
        /^\/tmp\/phantom-install\.[A-Za-z0-9]{6}$/,
        `${platform} ${label}: both variants stage under /tmp`,
      );
      assert.equal(fs.existsSync(stage), false, `${platform} ${label}: staging cleaned up on exit`);
    }
  }
});

test("the shared fallback is the only TMPDIR reference in both commands", () => {
  for (const platform of variants) {
    const command = displayedCommand(platform);
    const references = command.match(/\$\{?TMPDIR/g) ?? [];
    assert.equal(references.length, 1, `${platform}: TMPDIR appears exactly once`);
    assert.ok(
      command.includes('mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX"'),
      `${platform}: fallback lives in the mktemp template`,
    );
  }
});
