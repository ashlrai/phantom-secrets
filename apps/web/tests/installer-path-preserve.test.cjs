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

const marker = "# phantom-secrets PATH";
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
        assert.ok(after.toString().includes(`\n${marker}\n`), "marker not on its own line");
        assert.ok(after.toString().includes(`\n${c.wired}\n`), "PATH entry not on its own line");
        assert.equal(after.toString().split(marker).length - 1, 1, "marker duplicated");
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
          assert.ok(after.toString().includes(`\n${marker}\n`), "marker not on its own line");
          assert.ok(after.toString().includes(`\n${c.wired}\n`), "PATH entry not on its own line");
          assert.equal(after.toString().split(marker).length - 1, 1, "marker duplicated");
        }
      } finally {
        fs.rmSync(home, { recursive: true, force: true });
      }
    });
  }
}

// A comment full of shell metacharacters must not be expanded, split, or
// rewritten, whether it sits before the marker or is the unterminated last line.
const META_COMMENTS = [
  "# $(touch /tmp/pwned) `id` ${HOME} $PATH; rm -rf * | tee & >out <in 'q' \"d\" \\ !! {a,b} [a-z]* ~\n",
  "#\t;|&<>()$`\\\"'*?[]{}~!#%^ trailing  \r\n",
  "# $(echo hi) `echo hi` \\n \\\\ *",
];

for (const c of cases) {
  for (const comment of META_COMMENTS) {
    test(`PATH update keeps metacharacter comment ${JSON.stringify(comment)} byte-for-byte (${c.shell})`, () => {
      const home = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-path-"));
      try {
        const rc = path.join(home, c.rc);
        fs.mkdirSync(path.dirname(rc), { recursive: true });
        const before = Buffer.from(`# top\n${comment}`);
        fs.writeFileSync(rc, before);
        for (let i = 0; i < 2; i++) {
          const r = spawnSync("bash", ["-c", harness, "bash", "/opt/phantom/bin"], {
            env: { PATH: process.env.PATH, HOME: home, SHELL: `/bin/${c.shell}` },
            encoding: "utf8",
          });
          assert.equal(r.status, 0, r.stderr);
          const after = fs.readFileSync(rc);
          assert.ok(after.subarray(0, before.length).equals(before), "comment changed");
          assert.ok(after.toString().includes(`\n${marker}\n`), "marker not on its own line");
          assert.ok(after.toString().includes(`\n${c.wired}\n`), "PATH entry not on its own line");
          assert.equal(after.toString().split(marker).length - 1, 1, "marker duplicated");
        }
      } finally {
        fs.rmSync(home, { recursive: true, force: true });
      }
    });
  }
}

// A startup file that lacks a final newline must keep its last line intact
// while the marker and the PATH entry land on lines of their own — never
// glued onto user content. A last line ending in an odd backslash run is a
// line continuation: writing the marker directly after the gained terminator
// would let the shell fold it into the user's line the next time the file is
// sourced, so the update separates the block with a blank line there instead.
const UNTERMINATED = [
  "alias ll='ls -l'",
  "export NOTES=keep\\",
  "export ESCAPED=even\\\\",
  "   ",
];

for (const c of cases) {
  for (const content of UNTERMINATED) {
    test(`PATH entry stays a separate line in unterminated ${JSON.stringify(content)} (${c.shell})`, () => {
      const home = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-path-"));
      try {
        const rc = path.join(home, c.rc);
        fs.mkdirSync(path.dirname(rc), { recursive: true });
        const before = Buffer.from(content);
        fs.writeFileSync(rc, before);
        for (let i = 0; i < 2; i++) {
          const r = spawnSync("bash", ["-c", harness, "bash", "/opt/phantom/bin"], {
            env: { PATH: process.env.PATH, HOME: home, SHELL: `/bin/${c.shell}` },
            encoding: "utf8",
          });
          assert.equal(r.status, 0, r.stderr);
          const after = fs.readFileSync(rc);
          assert.ok(after.subarray(0, before.length).equals(before), "original bytes changed");
          const text = after.toString();
          assert.ok(text.includes(`\n${marker}\n`), "marker not on its own line");
          assert.ok(text.includes(`\n${c.wired}\n`), "PATH entry not on its own line");
          assert.equal(text.split(marker).length - 1, 1, "marker duplicated");
          if (c.shell !== "fish") {
            // fish syntax is not bash-sourceable; for bash and zsh files the
            // update must leave the file sourcing cleanly with PATH wired.
            const s = spawnSync("bash", ["-c",
              'source "$1" >/dev/null && case ":$PATH:" in *":/opt/phantom/bin:"*) exit 0;; *) exit 1;; esac',
              "bash", rc], { encoding: "utf8" });
            assert.equal(s.status, 0, s.stderr);
            assert.equal(s.stderr, "", "updated rc prints errors when sourced");
            if (content === "export NOTES=keep\\") {
              const v = spawnSync("bash", ["-c",
                'source "$1" >/dev/null && printf %s "$NOTES"', "bash", rc],
                { encoding: "utf8" });
              assert.equal(v.stdout, "keep",
                'line continuation corrupted user content to "keep#"');
            }
          }
        }
      } finally {
        fs.rmSync(home, { recursive: true, force: true });
      }
    });
  }
}

// If the second temporary file (the candidate PATH edit) cannot be created,
// the update fails without touching the startup file, and the first temporary
// file is removed rather than left behind. `mktemp` is shadowed by a function
// that fails only for the candidate template.
const failingCandidateHarness = [
  "set -euo pipefail",
  'say() { :; }',
  'mktemp() { case "$1" in *.candidate.*) return 1 ;; esac; command mktemp "$@"; }',
  fn("file_identity"),
  fn("file_link_count"),
  fn("add_to_user_path"),
  'add_to_user_path "$1"',
].join("\n");

for (const c of cases) {
  for (const existing of [true, false]) {
    test(`candidate temp file failure leaves ${existing ? "existing" : "missing"} rc unchanged and removes first temp file (${c.shell})`, () => {
      const home = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-path-"));
      try {
        const rc = path.join(home, c.rc);
        fs.mkdirSync(path.dirname(rc), { recursive: true });
        const before = Buffer.from(`# mine\n${UNRELATED}alias ll='ls -l'`);
        if (existing) fs.writeFileSync(rc, before);
        const r = spawnSync("bash", ["-c", failingCandidateHarness, "bash", "/opt/phantom/bin"], {
          env: { PATH: process.env.PATH, HOME: home, SHELL: `/bin/${c.shell}` },
          encoding: "utf8",
        });
        assert.notEqual(r.status, 0, "update should fail");
        if (existing) assert.ok(fs.readFileSync(rc).equals(before), "rc changed");
        else assert.equal(fs.existsSync(rc), false, "rc was created");
        assert.deepEqual(
          fs.readdirSync(path.dirname(rc)).filter((n) => n.startsWith(".phantom-path.")),
          [],
          "temporary file left behind",
        );
      } finally {
        fs.rmSync(home, { recursive: true, force: true });
      }
    });
  }
}
