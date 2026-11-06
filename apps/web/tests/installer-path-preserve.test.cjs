const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const script = fs.readFileSync(path.join(__dirname, "..", "public", "install.sh"), "utf8");

// Pull a top-level shell function out of install.sh so it runs alone, without
// the network or release steps.
function fn(name) {
  const m = script.match(new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?\\n\\}\\n`, "m"));
  assert.ok(m, `${name} not found in install.sh`);
  return m[0];
}

const harness = [
  "set -euo pipefail",
  'say() { :; }',
  fn("file_identity"),
  fn("file_link_count"),
  fn("add_to_user_path"),
  'add_to_user_path "$1"',
].join("\n");

const UNRELATED = "export COLUMNS=200\n";
const cases = [
  { shell: "bash", rc: ".bashrc", wired: 'export PATH="/opt/phantom/bin:$PATH"' },
  { shell: "zsh", rc: ".zshrc", wired: 'export PATH="/opt/phantom/bin:$PATH"' },
  { shell: "fish", rc: ".config/fish/config.fish", wired: 'set -gx PATH "/opt/phantom/bin" $PATH' },
];

for (const c of cases) {
  test(`PATH update keeps unrelated export COLUMNS byte-for-byte (${c.shell})`, () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-path-"));
    try {
      const rc = path.join(home, c.rc);
      fs.mkdirSync(path.dirname(rc), { recursive: true });
      // No trailing newline on the last line, plus odd spacing, to catch rewrites.
      const before = Buffer.from(`# mine\n${UNRELATED}export  COLUMNS = "x y"  \nalias ll='ls -l'`);
      fs.writeFileSync(rc, before);
      const run = () =>
        spawnSync("bash", ["-c", harness, "bash", "/opt/phantom/bin"], {
          env: { PATH: process.env.PATH, HOME: home, SHELL: `/bin/${c.shell}` },
          encoding: "utf8",
        });
      for (let i = 0; i < 2; i++) {
        const r = run();
        assert.equal(r.status, 0, r.stderr);
        const after = fs.readFileSync(rc);
        assert.ok(after.subarray(0, before.length).equals(before), "original bytes changed");
        assert.ok(after.toString().includes(c.wired));
        assert.equal(after.toString().split("# phantom-secrets PATH").length - 1, 1, "marker duplicated");
      }
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
}

// Unrelated PAGER and LESS lines: quoting, spacing, a `$PATH` mention, CRLF,
// and a last line without a trailing newline must all survive, before and
// after the marker.
const PAGER_LINES = [
  "export PAGER=less\n",
  'export PAGER="less -FRX"   # keep  spacing\n',
  "export PAGER='/usr/bin/less -R'\r\n",
  "export PAGER=\"$HOME/bin/pager:$PATH\"",
];
const LESS_LINES = [
  "export LESS=-R\n",
  'export LESS="-FRX --shift 5"\t# pager options\n',
  "export LESS='-i -j4 -z-4'\r\n",
  'export LESS="$LESS -S"',
];

for (const c of cases) {
  for (const line of [...PAGER_LINES, ...LESS_LINES]) {
    test(`PATH update keeps ${JSON.stringify(line)} byte-for-byte (${c.shell})`, () => {
      const home = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-path-"));
      try {
        const rc = path.join(home, c.rc);
        fs.mkdirSync(path.dirname(rc), { recursive: true });
        const before = Buffer.from(`# top\n${line}`);
        fs.writeFileSync(rc, before);
        for (let i = 0; i < 2; i++) {
          const r = spawnSync("bash", ["-c", harness, "bash", "/opt/phantom/bin"], {
            env: { PATH: process.env.PATH, HOME: home, SHELL: `/bin/${c.shell}` },
            encoding: "utf8",
          });
          assert.equal(r.status, 0, r.stderr);
          const after = fs.readFileSync(rc);
          assert.ok(after.subarray(0, before.length).equals(before), "unrelated line changed");
          assert.ok(after.toString().includes(c.wired));
          assert.equal(after.toString().split("# phantom-secrets PATH").length - 1, 1, "marker duplicated");
        }
      } finally {
        fs.rmSync(home, { recursive: true, force: true });
      }
    });
  }
}
