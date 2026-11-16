const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const script = fs.readFileSync(path.join(__dirname, "..", "public", "install.sh"), "utf8");
function fn(name) {
  const match = script.match(new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?\\n\\}\\n`, "m"));
  assert.ok(match, `${name} not found in install.sh`);
  return match[0];
}

// Run the installer's actual PATH setup without downloading a release.
const harness = [
  "set -euo pipefail",
  "say() { :; }",
  fn("file_identity"),
  fn("file_link_count"),
  fn("add_to_user_path"),
  'add_to_user_path "$1"',
].join("\n");

for (const { shell, rc, entry } of [
  { shell: "bash", rc: ".bashrc", entry: 'export PATH="/opt/phantom/bin:$PATH"' },
  { shell: "zsh", rc: ".zshrc", entry: 'export PATH="/opt/phantom/bin:$PATH"' },
  { shell: "fish", rc: ".config/fish/config.fish", entry: 'set -gx PATH "/opt/phantom/bin" $PATH' },
]) {
  test(`existing managed PATH entry is unchanged by repeated setup (${shell})`, () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-existing-path-"));
    try {
      const config = path.join(home, rc);
      fs.mkdirSync(path.dirname(config), { recursive: true });
      const original = Buffer.from(`# user settings\n# phantom-secrets PATH\n${entry}\nalias hi='echo hello'\n`);
      fs.writeFileSync(config, original);
      for (let i = 0; i < 2; i++) {
        const result = spawnSync("bash", ["-c", harness, "bash", "/opt/phantom/bin"], {
          env: { PATH: process.env.PATH, HOME: home, SHELL: `/bin/${shell}` },
          encoding: "utf8",
        });
        assert.equal(result.status, 0, result.stderr);
        assert.deepEqual(fs.readFileSync(config), original, "setup changed the existing configuration");
        assert.equal(fs.readdirSync(path.dirname(config)).length, 1, "temporary files remain");
      }
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
}
