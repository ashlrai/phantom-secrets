const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const script = fs.readFileSync(path.join(__dirname, "../public/install.sh"), "utf8");
function fn(name) {
  const match = script.match(new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?\\n\\}\\n`, "m"));
  assert.ok(match, `${name} not found in install.sh`);
  return match[0];
}
const harness = [
  "set -euo pipefail",
  "say() { :; }",
  fn("file_identity"),
  fn("file_link_count"),
  fn("add_to_user_path"),
  'add_to_user_path "$1"',
].join("\n");

for (const { shell, rcName, entry } of [
  { shell: "bash", rcName: ".bashrc", entry: 'export PATH="/opt/phantom/bin:$PATH"' },
  { shell: "zsh", rcName: ".zshrc", entry: 'export PATH="/opt/phantom/bin:$PATH"' },
  { shell: "fish", rcName: ".config/fish/config.fish", entry: 'set -gx PATH "/opt/phantom/bin" $PATH' },
]) {
  for (const existing of [true, false]) {
    test(`${shell} updates ${existing ? "existing" : "new"} rc under a parent with spaces without leaving temporary files`, () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom installer spaces "));
      const home = path.join(root, "home directory");
      const rc = path.join(home, rcName);
      const parent = path.dirname(rc);
      const original = "# existing configuration\n";
      try {
        fs.mkdirSync(parent, { recursive: true });
        fs.writeFileSync(path.join(parent, "unrelated file"), "keep");
        if (existing) fs.writeFileSync(rc, original);
        const expectedNames = [path.basename(rc), "unrelated file"].sort();
        const expected = `${existing ? original : ""}\n# phantom-secrets PATH\n${entry}\n`;
        for (let i = 0; i < 2; i++) {
          const result = spawnSync("bash", ["-c", harness, "bash", "/opt/phantom/bin"], {
            env: { PATH: process.env.PATH, HOME: home, SHELL: `/bin/${shell}` },
            encoding: "utf8",
          });
          assert.equal(result.status, 0, result.stderr);
          assert.equal(fs.readFileSync(rc, "utf8"), expected);
          assert.deepEqual(fs.readdirSync(parent).sort(), expectedNames);
          assert.equal(fs.readFileSync(path.join(parent, "unrelated file"), "utf8"), "keep");
        }
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    });
  }
}
