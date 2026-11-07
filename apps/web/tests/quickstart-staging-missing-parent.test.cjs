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

const guide = fs.readFileSync(path.join(__dirname, "../../../docs/quickstart-temp-fallback.md"), "utf8");
const release = load("src/lib/public-release.ts");
let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: () => [selected, () => {}] };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return release;
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});

function command(platform) {
  selected = platform;
  const card = find(QuickStart(), (node) => node.type === "article")[0];
  return find(card, (node) => typeof node.props.text === "string")[0].props.text;
}

// The staging setup is the verbatim subshell prologue through the EXIT trap;
// the displayed command runs it before the download. Keeping the real lines
// exercises the same quoting and failure behavior a copied command has.
function stagingSetup(displayed) {
  const lines = displayed.split("\n");
  assert.equal(lines[0], "(");
  const trap = lines.findIndex((line) => line.startsWith("trap "));
  assert.ok(trap > 0, "displayed command installs an EXIT trap");
  const download = lines.findIndex((line) => line.startsWith("curl "));
  assert.ok(download > trap, "the cleanup trap precedes the download");
  return lines.slice(0, trap + 1);
}

test("the staging command fails without reporting a created directory when TMPDIR does not exist", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-missing-parent-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const missing = path.join(tempRoot, "missing parent");
  const bin = path.join(tempRoot, "bin");
  fs.mkdirSync(bin);
  // A stub curl records any invocation so the run stays hermetic and proves
  // the failure precedes the download.
  const curlMarker = path.join(tempRoot, "curl-invoked");
  fs.writeFileSync(path.join(bin, "curl"), `#!/bin/bash\ntouch "${curlMarker}"\nexit 1\n`, { mode: 0o755 });
  const env = { PATH: `${bin}:/usr/bin:/bin`, HOME: path.join(tempRoot, "home"), TMPDIR: missing };

  for (const platform of ["macOS", "Linux"]) {
    // The exact displayed command: with a nonexistent TMPDIR it exits at
    // mktemp, before the trap is installed and before the download.
    const result = spawnSync("bash", ["-c", command(platform)], { env, encoding: "utf8", timeout: 30000 });
    assert.equal(result.status, 1, `${platform}: staging command fails`);
    assert.equal(result.signal, null, `${platform}: not killed by a signal`);
    assert.equal(result.stdout, "", `${platform}: no created directory is reported`);
    assert.match(result.stderr, /phantom-install\.|mktemp/i, `${platform}: stderr names the failure`);
    assert.equal(fs.existsSync(missing), false, `${platform}: the missing parent is not created`);
    assert.deepEqual(
      fs.readdirSync(tempRoot).filter((entry) => entry.startsWith("phantom-install.")),
      [],
      `${platform}: no staging directory exists`,
    );
    assert.equal(fs.existsSync(curlMarker), false, `${platform}: failure precedes the download`);
  }
});

test("the staging setup reports its directory only after mktemp succeeds", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-stage-report-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const present = path.join(tempRoot, "present parent");
  fs.mkdirSync(present);
  const missing = path.join(tempRoot, "missing parent");
  const env = (tmpdir) => ({ PATH: "/usr/bin:/bin", HOME: tempRoot, TMPDIR: tmpdir });

  for (const platform of ["macOS", "Linux"]) {
    // The real prologue plus a report line that a copied command would run
    // next: it prints the staged path only when mktemp created one.
    const script = [...stagingSetup(command(platform)), 'printf "staged=%s\\n" "$phantom_stage"', ")"].join("\n");
    const run = (tmpdir) => spawnSync("bash", ["-c", script], { env: env(tmpdir), encoding: "utf8", timeout: 30000 });

    const ok = run(present);
    assert.equal(ok.status, 0, `${platform}: ${ok.stderr}`);
    const [prefix, suffix] = ok.stdout.trim().split("/phantom-install.");
    assert.equal(prefix, `staged=${present}`, `${platform}: reports the staged directory`);
    assert.match(suffix, /^[A-Za-z0-9]{6}$/, `${platform}: unique template suffix`);
    assert.equal(fs.existsSync(ok.stdout.trim().slice("staged=".length)), false, `${platform}: trap removes the staged directory`);

    const bad = run(missing);
    assert.equal(bad.status, 1, `${platform}: missing parent fails`);
    assert.equal(bad.stdout, "", `${platform}: no directory is reported`);
  }
});

test("the fallback guide documents the missing-parent failure", () => {
  assert.match(guide, /must already exist and be writable/);
  assert.match(guide, /fail before the download instead\s+of retrying under `\/tmp`/);
});
