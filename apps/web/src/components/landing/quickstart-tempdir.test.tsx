import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { QuickStart } from "./QuickStart";

// Select the platform and return the command text exactly as displayed.
// QuickStart must already be rendered.
function displayedCommand(platform: string): string {
  const selector = screen.getByRole("group", { name: "Choose an operating system" });
  fireEvent.click(within(selector).getByRole("button", { name: platform }));
  const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
  assert.ok(card);
  const copy = within(card).getByRole("button", { name: /^Copy command:/ });
  return Array.from(copy.firstElementChild!.childNodes)
    .filter((node) => node.nodeType === Node.TEXT_NODE)
    .map((node) => node.textContent)
    .join("");
}

for (const platform of ["macOS", "Linux"]) {
  test(`${platform} displays a unique TMPDIR staging template`, () => {
    render(<QuickStart />);
    try {
      const displayed = displayedCommand(platform);

      // Each invocation gets its own directory; quotes preserve TMPDIR containing spaces.
      const stagingLines = displayed.split("\n").filter((line) => /\bmktemp\b/.test(line));
      assert.deepEqual(stagingLines, [
        'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"',
      ]);
    } finally {
      cleanup();
    }
  });
}

// The component quotes the staging template and every staged path so TMPDIR
// and HOME may contain spaces; the rendered text must keep exactly those
// quotes for the copied command to behave the way it is displayed.
const QUOTED_STAGED_PATHS = {
  unix: [
    '"${TMPDIR:-/tmp}/phantom-install.XXXXXX"',
    '"$phantom_stage/install.sh"',
    '"$phantom_installer"',
    '"$phantom_stage"',
    '"$HOME/.phantom-secrets/bin/phantom"',
    '"$HOME/.phantom-secrets/bin/phantom-mcp"',
  ],
  windows: [
    '"$env:USERPROFILE\\.phantom-secrets\\bin\\phantom.exe"',
    '"$env:USERPROFILE\\.phantom-secrets\\bin\\phantom-mcp.exe"',
  ],
} as const;

test("displayed temporary-directory commands keep every quoted path", () => {
  render(<QuickStart />);
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    for (const platform of ["macOS", "Windows", "Linux"]) {
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      const copy = within(card).getByRole("button", { name: /^Copy command:/ });
      const displayed = Array.from(copy.firstElementChild!.childNodes)
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent)
        .join("");

      const quoted = platform === "Windows" ? QUOTED_STAGED_PATHS.windows : QUOTED_STAGED_PATHS.unix;
      for (const fragment of quoted) {
        assert.ok(displayed.includes(fragment), `${platform}: displayed command keeps ${fragment}`);
      }
      if (platform !== "Windows") {
        assert.ok(
          displayed.includes('phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"'),
          `${platform}: mktemp template keeps both quote pairs`,
        );
      }
      // Removing each quoted span must leave no staged-path expansion behind:
      // a path outside quotes would split on spaces in TMPDIR or HOME.
      const unquoted = quoted.reduce((text, fragment) => text.split(fragment).join(""), displayed);
      if (platform === "Windows") {
        assert.doesNotMatch(unquoted, /\$env:USERPROFILE/, platform);
      } else {
        assert.doesNotMatch(unquoted, /\$[A-Za-z_{]/, `${platform}: unquoted staged-path expansion`);
      }
    }
  } finally {
    cleanup();
  }
});

test("every displayed installer stages under a temporary directory and cleans up", () => {
  render(<QuickStart />);
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    for (const platform of ["macOS", "Windows", "Linux"]) {
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      const copy = within(card).getByRole("button", { name: /^Copy command:/ });
      const displayed = Array.from(copy.firstElementChild!.childNodes)
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent)
        .join("");

      if (platform === "Windows") {
        assert.match(displayed, /\$Installer = Join-Path \$env:TEMP \('phantom-install-[^\n]+\[Guid\]::NewGuid\(\)/);
        assert.match(displayed, /Invoke-WebRequest [^\n]+-OutFile \$Installer/);
        assert.match(displayed, /try \{[\s\S]*Invoke-WebRequest[\s\S]*\} finally \{\s*Remove-Item -LiteralPath \$Installer -Force -ErrorAction SilentlyContinue\s*\}/);
      } else {
        assert.ok(displayed.includes('phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"'), platform);
        assert.ok(displayed.includes('phantom_installer="$phantom_stage/install.sh"'), platform);
        assert.match(displayed, /curl [^\n]+--output "\$phantom_installer"/);
        const cleanup = displayed.indexOf(`trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT`);
        assert.ok(cleanup >= 0 && cleanup < displayed.indexOf("curl "), `${platform}: install cleanup before download`);
      }
    }
  } finally {
    cleanup();
  }
});

// Run the displayed staging prologue (set -e through the EXIT trap) in real bash
// with TMPDIR unset, so the `${TMPDIR:-/tmp}` default is exercised, not just read.
for (const platform of ["macOS", "Linux"]) {
  test(`${platform} staging falls back to /tmp when TMPDIR is unset and cleans up`, () => {
    render(<QuickStart />);
    let displayed = "";
    try {
      displayed = displayedCommand(platform);
    } finally {
      cleanup();
    }

    const lines = displayed.split("\n");
    const trap = lines.findIndex((line) => line.startsWith("trap "));
    assert.ok(trap > 0, `${platform}: displayed command installs an EXIT trap`);
    // Keep the real prologue; replace the download/install steps with a fixture
    // file standing in for the installer so nothing touches the network.
    const script = [
      ...lines.slice(0, trap + 1),
      'printf "%s\\n" "$phantom_stage"',
      'printf fixture > "$phantom_installer"',
      ")",
    ].join("\n");

    const env = { ...process.env };
    delete env.TMPDIR;
    const result = spawnSync("bash", ["-c", script], { env, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const stage = result.stdout.trim();
    assert.match(stage, /^\/tmp\/phantom-install\.[A-Za-z0-9]{6}$/, `${platform}: staged under /tmp`);
    assert.equal(existsSync(stage), false, `${platform}: fixture and staging directory removed on exit`);
  });
}

// The page promises /tmp when TMPDIR is "unset or empty"; `${TMPDIR:-/tmp}`
// (colon form) covers both, so an exported-but-empty TMPDIR must also stage
// under /tmp rather than at a root-relative "/phantom-install.XXXXXX".
for (const platform of ["macOS", "Linux"]) {
  test(`${platform} staging falls back to /tmp when TMPDIR is empty`, () => {
    render(<QuickStart />);
    let displayed = "";
    try {
      displayed = displayedCommand(platform);
    } finally {
      cleanup();
    }

    const lines = displayed.split("\n");
    const trap = lines.findIndex((line) => line.startsWith("trap "));
    assert.ok(trap > 0, `${platform}: displayed command installs an EXIT trap`);
    const script = [
      ...lines.slice(0, trap + 1),
      'printf "%s\\n" "$phantom_stage"',
      'printf fixture > "$phantom_installer"',
      ")",
    ].join("\n");

    const result = spawnSync("bash", ["-c", script], {
      env: { ...process.env, TMPDIR: "" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    const stage = result.stdout.trim();
    assert.match(stage, /^\/tmp\/phantom-install\.[A-Za-z0-9]{6}$/, `${platform}: staged under /tmp`);
    assert.equal(existsSync(stage), false, `${platform}: fixture and staging directory removed on exit`);
  });
}

// Same real prologue, but TMPDIR names a directory whose path contains a
// space: only a single-argument template lets mktemp stage inside it, so a
// zero exit status plus a stage rooted in that parent proves the quoted
// command keeps the temporary parent one path.
for (const platform of ["macOS", "Linux"]) {
  test(`${platform} staging treats a space-containing TMPDIR parent as one path`, (t) => {
    render(<QuickStart />);
    let displayed = "";
    try {
      displayed = displayedCommand(platform);
    } finally {
      cleanup();
    }

    const lines = displayed.split("\n");
    const trap = lines.findIndex((line) => line.startsWith("trap "));
    assert.ok(trap > 0, `${platform}: displayed command installs an EXIT trap`);
    const script = [
      ...lines.slice(0, trap + 1),
      'printf "%s\\n" "$phantom_stage"',
      'printf fixture > "$phantom_installer"',
      ")",
    ].join("\n");

    const parent = mkdtempSync(path.join(tmpdir(), "phantom stage parent "));
    t.after(() => rmSync(parent, { recursive: true, force: true }));
    const result = spawnSync("bash", ["-c", script], {
      env: { ...process.env, TMPDIR: parent },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    const stage = result.stdout.trim();
    assert.equal(path.dirname(stage), parent, `${platform}: staged inside the space-containing parent`);
    assert.match(path.basename(stage), /^phantom-install\.[A-Za-z0-9]{6}$/, `${platform}: unique staging name`);
    assert.equal(existsSync(stage), false, `${platform}: fixture and staging directory removed on exit`);
  });
}

// A failing mktemp binary is a different cause than a bad TMPDIR: the parent
// exists and is writable, but the first creation step still cannot produce a
// staging directory. set -e must then end the subshell nonzero before the
// download, so the full displayed command runs here verbatim against a PATH
// stub; the curl spy proves the failure stays ahead of the network.
for (const platform of ["macOS", "Linux"]) {
  test(`${platform} command exits nonzero when mktemp itself fails`, (t) => {
    render(<QuickStart />);
    let displayed = "";
    try {
      displayed = displayedCommand(platform);
    } finally {
      cleanup();
    }

    const tempRoot = mkdtempSync(path.join(tmpdir(), "phantom-mktemp-failure-"));
    t.after(() => rmSync(tempRoot, { recursive: true, force: true }));
    const bin = path.join(tempRoot, "bin");
    mkdirSync(bin);
    const curlMarker = path.join(tempRoot, "curl-invoked");
    writeFileSync(
      path.join(bin, "mktemp"),
      "#!/bin/sh\nprintf 'stub mktemp: forced failure\\n' >&2\nexit 1\n",
      { mode: 0o755 },
    );
    writeFileSync(
      path.join(bin, "curl"),
      `#!/bin/sh\ntouch "${curlMarker}"\nexit 0\n`,
      { mode: 0o755 },
    );

    const result = spawnSync("bash", ["-c", displayed], {
      env: { ...process.env, PATH: `${bin}:/usr/bin:/bin`, HOME: tempRoot, TMPDIR: tempRoot },
      encoding: "utf8",
      timeout: 30000,
    });
    assert.notEqual(result.status, 0, `${platform}: a failed mktemp must fail the command`);
    assert.match(result.stderr, /stub mktemp: forced failure/, `${platform}: mktemp is the failing step`);
    assert.equal(existsSync(curlMarker), false, `${platform}: the download never runs after staging fails`);
  });
}

// The curl spy above only covers the download. Every later staging step must
// also stay unreached: checksum, installer execution, cleanup (rm/rmdir, which
// would act on an empty $phantom_stage), and the version checks. Each is a
// logging PATH shim; the log must stay empty and nothing may appear on stdout.
for (const platform of ["macOS", "Linux"]) {
  test(`${platform} stubbed mktemp failure stops every later staging step`, (t) => {
    render(<QuickStart />);
    let displayed = "";
    try {
      displayed = displayedCommand(platform);
    } finally {
      cleanup();
    }

    const tempRoot = mkdtempSync(path.join(tmpdir(), "phantom-mktemp-stops-"));
    t.after(() => rmSync(tempRoot, { recursive: true, force: true }));
    const bin = path.join(tempRoot, "bin");
    mkdirSync(bin);
    const log = path.join(tempRoot, "later-steps.log");
    writeFileSync(
      path.join(bin, "mktemp"),
      "#!/bin/sh\nprintf 'stub mktemp: forced failure\\n' >&2\nexit 1\n",
      { mode: 0o755 },
    );
    // Shims for each step after staging; a call appends its name to the log.
    for (const step of ["curl", "shasum", "sha256sum", "bash", "rm", "rmdir", "phantom", "phantom-mcp"]) {
      writeFileSync(path.join(bin, step), `#!/bin/sh\nprintf '%s\\n' ${step} >> "${log}"\nexit 0\n`, { mode: 0o755 });
    }
    // Bash itself is the interpreter under test, so run it by absolute path;
    // the bin shim above only intercepts the displayed `bash "$phantom_installer"`.
    const realBash = spawnSync("sh", ["-c", "command -v bash"], { encoding: "utf8" }).stdout.trim();
    assert.ok(realBash, "a real bash is available");
    const result = spawnSync(realBash, ["-c", displayed], {
      env: { ...process.env, PATH: `${bin}:/usr/bin:/bin`, HOME: bin, TMPDIR: tempRoot },
      encoding: "utf8",
      timeout: 30000,
    });
    assert.notEqual(result.status, 0, `${platform}: a failed mktemp must fail the command`);
    assert.match(result.stderr, /stub mktemp: forced failure/, `${platform}: mktemp is the failing step`);
    assert.equal(result.stdout, "", `${platform}: no version or checksum output after failure`);
    assert.equal(existsSync(log) ? readFileSync(log, "utf8") : "", "", `${platform}: no later staging step ran`);
  });
}

// Every displayed snippet names its temporary files with the same
// `phantom-install` prefix, so users and agents recognize leftovers the same
// way on every platform, and no other temporary name appears.
test("every displayed snippet uses the phantom-install temporary prefix", () => {
  render(<QuickStart />);
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    for (const platform of ["macOS", "Windows", "Linux"]) {
      fireEvent.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      const copy = within(card).getByRole("button", { name: /^Copy command:/ });
      const displayed = Array.from(copy.firstElementChild!.childNodes)
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent)
        .join("");

      const tempLines = displayed.split("\n").filter((line) => /\bmktemp\b|\$env:TEMP/.test(line));
      assert.equal(tempLines.length, 1, `${platform}: exactly one temporary name`);
      const prefix =
        platform === "Windows"
          ? /Join-Path \$env:TEMP \('phantom-install-/
          : /mktemp -d "\$\{TMPDIR:-\/tmp\}\/phantom-install\.XXXXXX"/;
      assert.match(tempLines[0], prefix, `${platform}: temporary name starts with phantom-install`);
    }
  } finally {
    cleanup();
  }
});
