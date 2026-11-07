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

// The selected platform card's copy button renders first; the two shared
// STEPS commands ("phantom --version…" and "phantom init") follow it and
// create no staging directory.
function platformCommand(platform) {
  selected = platform;
  return find(QuickStart(), (node) => typeof node.props.text === "string")[0].props.text;
}

// Staging commands are the displayed platform commands that create a
// temporary staging directory: the mktemp subshells on the Unix cards. The
// Windows block stages a single file under $env:TEMP and is not one.
function stagingCommands() {
  const order = find(QuickStart(), (node) => node.type === "button").map((node) => node.props.children);
  return order
    .map((platform) => ({ platform, command: platformCommand(platform) }))
    .filter(({ command }) => /\bmktemp -d\b/.test(command));
}

test("exactly two staging commands are displayed; the second is the Linux card's", () => {
  assert.deepEqual(stagingCommands().map(({ platform }) => platform), ["macOS", "Linux"]);
});

test("the second staging command stages a distinct directory on each of two runs and cleans up both", (t) => {
  const staging = stagingCommands();
  assert.equal(staging.length, 2, "expected two staging commands");
  const { platform, command } = staging[1];

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-stage-repeat-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const home = path.join(tempRoot, "home");
  // A space in the temporary parent keeps the run honest about the quoting
  // the displayed command relies on.
  const tmp = path.join(tempRoot, "tmp with spaces");
  const bin = path.join(tempRoot, "bin");
  const installedBin = path.join(home, ".phantom-secrets", "bin");
  for (const dir of [tmp, bin, installedBin]) fs.mkdirSync(dir, { recursive: true });
  const stageLog = path.join(tempRoot, "stages.log");

  // A hermetic curl records the staging directory it was handed, then writes
  // a no-op installer so the verbatim displayed command completes without a
  // network; the checksum tool and installed binaries are stubbed the same
  // way, while mktemp, the trap, rm, and rmdir stay real.
  fs.writeFileSync(path.join(bin, "curl"), `#!/bin/bash
while [ "$1" != "--output" ]; do shift; done
printf '%s\\n' "$(dirname "$2")" >> "${stageLog}"
printf '#!/bin/bash\\nexit 0\\n' > "$2"
`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "sha256sum"), "#!/bin/bash\ncat >/dev/null\n", { mode: 0o755 });
  // The version-check paths must exist verbatim, but the stubs behind them
  // are reached through relative symlinks: some hardened macOS policies
  // refuse to exec a temp file literally named phantom*, and a symlink keeps
  // the displayed path working there and on Linux the same way.
  for (const binary of ["phantom", "phantom-mcp"]) {
    fs.writeFileSync(path.join(installedBin, `.${binary}-stub`), "#!/bin/bash\nexit 0\n", { mode: 0o755 });
    fs.symlinkSync(`.${binary}-stub`, path.join(installedBin, binary));
  }
  const env = { PATH: `${bin}:/usr/bin:/bin`, HOME: home, TMPDIR: tmp };

  const stages = [];
  for (const run of [1, 2]) {
    const result = spawnSync("bash", ["-c", command], { env, encoding: "utf8", timeout: 30000 });
    assert.equal(result.status, 0, `${platform} run ${run}: ${result.stderr}`);
    assert.equal(result.signal, null, `${platform} run ${run}: not killed by a signal`);

    const recorded = fs.readFileSync(stageLog, "utf8").trim().split("\n");
    assert.equal(recorded.length, run, `${platform} run ${run}: exactly one staging directory created`);
    const stage = recorded[run - 1];
    assert.equal(path.dirname(stage), tmp, `${platform} run ${run}: staged under TMPDIR`);
    assert.match(path.basename(stage), /^phantom-install\.[A-Za-z0-9]{6}$/, `${platform} run ${run}: unique staging name`);
    assert.equal(fs.existsSync(stage), false, `${platform} run ${run}: EXIT trap removed the staging directory`);
    stages.push(stage);
  }

  assert.notEqual(stages[0], stages[1], `${platform}: repeated runs stage distinct directories`);
  assert.deepEqual(fs.readdirSync(tmp), [], `${platform}: no staging residue remains after both runs`);
});
