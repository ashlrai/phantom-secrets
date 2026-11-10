const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const script = fs.readFileSync(path.join(__dirname, '../public/install.sh'), 'utf8');
const functions = ['file_identity', 'file_link_count', 'add_to_user_path'].map((name) => {
  const match = script.match(new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?\\n\\}\\n`, 'm'));
  assert.ok(match, `${name} is missing`);
  return match[0];
}).join('\n');

for (const [shell, rcName, entry] of [
  ['bash', '.bashrc', 'export PATH="/opt/phantom/bin:$PATH"'],
  ['zsh', '.zshrc', 'export PATH="/opt/phantom/bin:$PATH"'],
  ['fish', '.config/fish/config.fish', 'set -gx PATH "/opt/phantom/bin" $PATH'],
]) {
  test(`successful PATH update preserves an existing ${shell} configuration exactly`, (t) => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'phantom-config-'));
    t.after(() => fs.rmSync(home, { recursive: true, force: true }));
    const rc = path.join(home, rcName);
    fs.mkdirSync(path.dirname(rc), { recursive: true });
    const original = '# personal settings\nexport EDITOR="vim -f"\nalias gs="git status"\n\n# retain spacing  \n';
    fs.writeFileSync(rc, original, { mode: 0o640 });
    const expected = `${original}\n# phantom-secrets PATH\n${entry}\n`;
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = spawnSync('bash', ['-c', `set -euo pipefail\nsay() { :; }\n${functions}\nadd_to_user_path "$1"`, 'bash', '/opt/phantom/bin'], {
        env: { HOME: home, SHELL: `/bin/${shell}`, PATH: process.env.PATH }, encoding: 'utf8',
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(fs.readFileSync(rc, 'utf8'), expected);
      assert.equal(fs.statSync(rc).mode & 0o777, 0o640);
    }
  });
}
