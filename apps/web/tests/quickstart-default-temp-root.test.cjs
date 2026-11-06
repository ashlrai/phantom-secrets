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

let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: () => [selected, () => {}] };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});

// The generated first command is the selected platform card's install
// command; the only other text props are the two follow-up step commands
// (`phantom --version`… and `phantom init`), which create no directory.
function firstCommand(platform) {
  selected = platform;
  return find(QuickStart(), (node) => typeof node.props.text === "string")[0].props.text;
}

// The verbatim generated lines from the subshell open through the EXIT trap,
// run under an environment where TMPDIR does not exist at all, then the
// staged path and its physical resolution are reported before the displayed
// cleanup trap runs. The leading guard proves the fallback is exercised:
// if TMPDIR reached the child this fails instead of silently passing.
function stagingScript(displayed) {
  const lines = displayed.split("\n");
  assert.equal(lines[0], "(");
  const trap = lines.findIndex((line) => line.startsWith("trap "));
  assert.ok(trap > 0, "displayed command installs an EXIT trap");
  return [
    'test -z "${TMPDIR+x}" || { echo "TMPDIR reached the child" >&2; exit 1; }',
    ...lines.slice(0, trap + 1),
    'test -d "$phantom_stage"',
    'printf fixture > "$phantom_installer"',
    'printf "%s\\n" "$phantom_stage"',
    'cd "$phantom_stage" && pwd -P',
    ")",
  ].join("\n");
}

for (const platform of ["macOS", "Linux"]) {
  test(`${platform}: the generated first command creates its staging directory under /tmp when TMPDIR is unset`, (t) => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-temp-root-"));
    t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
    const env = { PATH: "/usr/bin:/bin", HOME: path.join(tempRoot, "home") };
    fs.mkdirSync(env.HOME);
    assert.ok(!("TMPDIR" in env));

    const result = spawnSync("bash", ["-c", stagingScript(firstCommand(platform))], {
      env, encoding: "utf8", timeout: 30000,
    });
    assert.equal(result.status, 0, `${platform}: ${result.stderr}`);
    assert.equal(result.signal, null, `${platform}: not killed by a signal`);

    const [stage, resolved] = result.stdout.trim().split("\n");
    // The reported path keeps the literal /tmp default as its parent...
    assert.equal(path.dirname(stage), "/tmp", `${platform}: unset TMPDIR selects the /tmp default`);
    assert.match(path.basename(stage), /^phantom-install\.[A-Za-z0-9]{6}$/, `${platform}: unique staging name`);
    // ...and the directory really existed under the physical temporary root
    // (which may be a symlink, e.g. /private/tmp on macOS) before the EXIT
    // trap removed it and the fixture installer.
    assert.equal(path.dirname(resolved), fs.realpathSync("/tmp"), `${platform}: created under the real /tmp`);
    assert.equal(fs.existsSync(stage), false, `${platform}: EXIT trap removed the staging directory`);
  });
}

// The documented fallback covers "unset or empty"; an empty TMPDIR must
// select the same default rather than staging relative to the cwd.
test("an empty TMPDIR selects the same /tmp default", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-temp-root-empty-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const cwd = path.join(tempRoot, "cwd");
  fs.mkdirSync(cwd);
  const env = { PATH: "/usr/bin:/bin", HOME: tempRoot, TMPDIR: "" };

  const result = spawnSync("bash", ["-c", stagingScript(firstCommand("macOS")).replace(
    'test -z "${TMPDIR+x}" || { echo "TMPDIR reached the child" >&2; exit 1; }',
    'test -z "$TMPDIR" || { echo "TMPDIR is not empty" >&2; exit 1; }',
  )], { env, cwd, encoding: "utf8", timeout: 30000 });
  assert.equal(result.status, 0, result.stderr);
  const [stage] = result.stdout.trim().split("\n");
  assert.equal(path.dirname(stage), "/tmp");
  assert.equal(fs.existsSync(stage), false, "EXIT trap removed the staging directory");
  assert.deepEqual(fs.readdirSync(cwd), [], "nothing staged relative to the cwd");
});
