const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const script = fs.readFileSync(path.join(__dirname, "..", "public", "install.sh"), "utf8");

function fn(name) {
  const m = script.match(new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?\\n\\}\\n`, "m"));
  assert.ok(m, `${name} not found in install.sh`);
  return m[0];
}

const harness = [
  "set -euo pipefail",
  "say() { :; }",
  fn("file_identity"),
  fn("file_link_count"),
  fn("add_to_user_path"),
  'add_to_user_path "$1"',
].join("\n");

const realMktemp = spawnSync("sh", ["-c", "command -v mktemp"], { encoding: "utf8" }).stdout.trim();

const cases = [
  { shell: "bash", rc: ".bashrc" },
  { shell: "zsh", rc: ".zshrc" },
  { shell: "fish", rc: ".config/fish/config.fish" },
];

// A mktemp shim that fails only for the candidate file, so the installer gets
// as far as reading the existing rc before the failure.
function withFailingCandidateMktemp(fnBody) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-path-"));
  try {
    const shimDir = path.join(root, "shim");
    fs.mkdirSync(shimDir);
    fs.writeFileSync(
      path.join(shimDir, "mktemp"),
      `#!/bin/sh\ncase "$*" in *.phantom-path.candidate.*) exit 1 ;; esac\nexec "${realMktemp}" "$@"\n`,
      { mode: 0o755 },
    );
    const home = path.join(root, "home");
    fs.mkdirSync(home);
    fnBody(home, shimDir);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function run(home, shimDir, shell) {
  return spawnSync("bash", ["-c", harness, "bash", "/opt/phantom/bin"], {
    env: { PATH: `${shimDir}:${process.env.PATH}`, HOME: home, SHELL: `/bin/${shell}` },
    encoding: "utf8",
  });
}

function leftovers(dir) {
  return fs.readdirSync(dir).filter((n) => n.startsWith(".phantom-path."));
}

for (const c of cases) {
  test(`candidate temp file failure leaves existing rc unchanged (${c.shell})`, () => {
    withFailingCandidateMktemp((home, shimDir) => {
      const rc = path.join(home, c.rc);
      fs.mkdirSync(path.dirname(rc), { recursive: true });
      fs.writeFileSync(rc, "# mine\nalias ll='ls -l'", { mode: 0o640 });
      const before = fs.readFileSync(rc);
      const modeBefore = fs.statSync(rc).mode;

      const r = run(home, shimDir, c.shell);

      assert.notEqual(r.status, 0, "installer should report failure");
      assert.ok(fs.readFileSync(rc).equals(before), "rc bytes changed");
      assert.equal(fs.statSync(rc).mode, modeBefore, "rc mode changed");
      assert.deepEqual(leftovers(path.dirname(rc)), [], "temp files left behind");
    });
  });

  test(`candidate temp file failure does not create a missing rc (${c.shell})`, () => {
    withFailingCandidateMktemp((home, shimDir) => {
      const rc = path.join(home, c.rc);

      const r = run(home, shimDir, c.shell);

      assert.notEqual(r.status, 0, "installer should report failure");
      assert.equal(fs.existsSync(rc), false, "rc was created");
      assert.deepEqual(leftovers(path.dirname(rc)), [], "temp files left behind");
    });
  });
}
