const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const script = fs.readFileSync(path.join(__dirname, "..", "public", "install.sh"), "utf8");
const match = script.match(/^add_to_user_path\(\) \{\n[\s\S]*?\n\}\n/m);
assert.ok(match, "add_to_user_path not found in install.sh");

// Run the actual function without downloading a release. The stub delegates
// the first creation to the system mktemp and fails only the candidate creation.
const harness = [
  "set -euo pipefail",
  'mktemp() {',
  '  case "$1" in',
  '    */.phantom-path.before.XXXXXX)',
  '      command mktemp "$1" > "$RECORD"',
  '      cat "$RECORD" ;;',
  '    */.phantom-path.candidate.XXXXXX)',
  '      [ -f "$(cat "$RECORD")" ] || exit 2',
  '      printf candidate >> "$RECORD.calls"',
  '      return 1 ;;',
  '    *) exit 3 ;;',
  '  esac',
  '}',
  match[0],
  'add_to_user_path "$1"',
].join("\n");

for (const [shell, rcName] of [["bash", ".bashrc"], ["zsh", ".zshrc"], ["fish", ".config/fish/config.fish"]]) {
  test(`candidate creation failure preserves ${shell} config and cleans the first temp file`, () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-candidate-failure-"));
    try {
      const rc = path.join(home, rcName);
      const record = path.join(home, "created-temp");
      fs.mkdirSync(path.dirname(rc), { recursive: true });
      const before = Buffer.from("# existing config\r\nexport EXAMPLE='keep spacing'  ");
      fs.writeFileSync(rc, before, { mode: 0o640 });
      const stat = fs.statSync(rc);
      const result = spawnSync("bash", ["-c", harness, "bash", "/opt/phantom/bin"], {
        env: { PATH: process.env.PATH, HOME: home, SHELL: `/bin/${shell}`, RECORD: record },
        encoding: "utf8",
      });
      assert.equal(result.status, 1, result.stderr);
      assert.equal(fs.readFileSync(`${record}.calls`, "utf8"), "candidate", "candidate creation was attempted");
      const firstTemp = fs.readFileSync(record, "utf8").trim();
      assert.match(path.basename(firstTemp), /^\.phantom-path\.before\./);
      assert.equal(fs.existsSync(firstTemp), false, "first temporary file was removed");
      assert.deepEqual(fs.readFileSync(rc), before, "original config bytes changed");
      const after = fs.statSync(rc);
      assert.equal(after.ino, stat.ino, "original config was replaced");
      assert.equal(after.mode, stat.mode, "original config permissions changed");
      assert.deepEqual(fs.readdirSync(path.dirname(rc)).filter((name) => name.startsWith(".phantom-path.")), []);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
}
