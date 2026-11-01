const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { JSDOM } = require("jsdom");
const ts = require("typescript");

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "http://localhost/" });
global.window = dom.window;
global.document = dom.window.document;
Object.defineProperty(global, "navigator", { value: dom.window.navigator, configurable: true });
global.HTMLElement = dom.window.HTMLElement;

const React = require("react");
const { cleanup, fireEvent, render, screen, waitFor, within } = require("@testing-library/react");
const userEvent = require("@testing-library/user-event").default;

function compile(file, localRequire) {
  const input = fs.readFileSync(path.join(__dirname, "../src", file), "utf8");
  const output = ts.transpileModule(input, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    fileName: file,
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, localRequire);
  return exports;
}

const icons = compile("components/landing/Icons.tsx", require);
const release = compile("lib/public-release.ts", require);
const copyButton = compile("components/landing/CopyButton.tsx", (name) => {
  if (name === "./Icons") return icons;
  if (name === "@/lib/posthog") return { capturePostHog: async () => {} };
  return require(name);
});
const { QuickStart } = compile("components/landing/QuickStart.tsx", (name) => {
  if (name === "./CopyButton") return copyButton;
  if (name === "@/lib/public-release") return release;
  if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
  return require(name);
});

test("platform selection shows only the chosen instructions and exposes its pressed state", async () => {
  const user = userEvent.setup();
  const platforms = {
    macOS: {
      detail: "Uses Keychain when available.",
      command: "shasum -a 256 -c -",
      assets: ["phantom-aarch64-apple-darwin.tar.gz", "phantom-x86_64-apple-darwin.tar.gz"],
    },
    Windows: {
      detail: "Uses current-user Credential Manager when available.",
      command: "Get-FileHash -Algorithm SHA256",
      assets: ["phantom-aarch64-pc-windows-msvc.zip", "phantom-x86_64-pc-windows-msvc.zip"],
    },
    Linux: {
      detail: "Published GNU targets enforce a glibc 2.35 symbol ceiling",
      command: "sha256sum -c -",
      assets: ["phantom-aarch64-unknown-linux-gnu.tar.gz", "phantom-x86_64-unknown-linux-gnu.tar.gz"],
    },
  };
  render(React.createElement(QuickStart));
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    const check = (selected) => {
      const controls = within(selector).getAllByRole("button");
      assert.equal(controls.length, 3);
      assert.equal(within(selector).getByRole("button", { name: selected, pressed: true }).textContent, selected);
      for (const name of Object.keys(platforms).filter((name) => name !== selected)) {
        assert.ok(within(selector).getByRole("button", { name, pressed: false }));
        assert.equal(screen.queryByRole("heading", { level: 3, name }), null);
      }
      const card = screen.getByRole("heading", { level: 3, name: selected }).closest("article");
      assert.ok(card);
      assert.equal(document.querySelectorAll(".platform-install-card").length, 1);
      assert.ok(card.textContent.includes(platforms[selected].detail));
      assert.ok(within(card).getByRole("button", { name: /^Copy command:/ }).textContent.includes(platforms[selected].command));
      const links = within(card).getAllByRole("link");
      for (const asset of platforms[selected].assets) {
        assert.ok(links.some((link) => link.getAttribute("href").endsWith(`/${asset}`)), asset);
        assert.ok(links.some((link) => link.getAttribute("href").endsWith(`/${asset}.sha256`)), `${asset} checksum`);
      }
    };

    check("macOS");
    await user.click(within(selector).getByRole("button", { name: "Windows" }));
    check("Windows");
    const linux = within(selector).getByRole("button", { name: "Linux" });
    linux.focus();
    await user.keyboard(" ");
    assert.equal(document.activeElement, linux);
    check("Linux");
    await user.click(within(selector).getByRole("button", { name: "macOS" }));
    check("macOS");
  } finally {
    cleanup();
  }
});

test("quick start remains a region named by its visible heading when switching platforms", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const name = "Install on your OS. Then protect one project.";
    const region = screen.getByRole("region", { name });
    const heading = within(region).getByRole("heading", { level: 2, name });
    assert.equal(region.getAttribute("aria-labelledby"), heading.id);
    assert.ok(heading.id);

    for (const platform of ["Windows", "Linux", "macOS"]) {
      await user.click(within(region).getByRole("button", { name: platform }));
      assert.equal(screen.getByRole("region", { name }), region);
      assert.equal(within(region).getByRole("heading", { level: 2, name }), heading);
      assert.ok(within(region).getByRole("heading", { level: 3, name: platform }));
    }
  } finally {
    cleanup();
  }
});

test("reduced motion keeps platform commands available without animation events", async () => {
  const originalMatchMedia = window.matchMedia;
  window.matchMedia = (query) => ({
    matches: query === "(prefers-reduced-motion: reduce)",
    media: query,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
  });
  const user = userEvent.setup();
  try {
    render(React.createElement(QuickStart));
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    const check = (platform, commandPart) => {
      const active = within(selector).getByRole("button", { name: platform });
      for (const button of within(selector).getAllByRole("button")) {
        assert.equal(button.getAttribute("aria-pressed"), String(button === active));
      }
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      assert.equal(document.querySelectorAll(".platform-install-card").length, 1);
      const command = within(card).getByRole("button", { name: /^Copy command:/ });
      assert.ok(command.textContent.includes(commandPart), `${platform}: command is immediately available`);
      assert.equal(command.disabled, false);
      return command;
    };

    check("macOS", "shasum -a 256 -c -");
    // Dispatch no animation or transition events: selection must update on activation alone.
    fireEvent.click(within(selector).getByRole("button", { name: "Windows" }));
    check("Windows", "Get-FileHash -Algorithm SHA256");
    const linux = within(selector).getByRole("button", { name: "Linux" });
    linux.focus();
    await user.keyboard("{Enter}");
    assert.equal(document.activeElement, linux);
    const command = check("Linux", "sha256sum -c -");
    await user.click(command);
    assert.ok((await navigator.clipboard.readText()).includes("sha256sum -c -"));
    fireEvent.click(within(selector).getByRole("button", { name: "macOS" }));
    check("macOS", "shasum -a 256 -c -");
  } finally {
    cleanup();
    window.matchMedia = originalMatchMedia;
  }
});

test("re-selecting the active platform preserves its selection and install command", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    for (const [platform, commandPart] of [
      ["macOS", "shasum -a 256 -c -"],
      ["Windows", "Get-FileHash -Algorithm SHA256"],
      ["Linux", "sha256sum -c -"],
      ["macOS", "shasum -a 256 -c -"],
    ]) {
      const active = within(selector).getByRole("button", { name: platform });
      if (active.getAttribute("aria-pressed") !== "true") await user.click(active);
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      const command = within(card).getByRole("button", { name: /^Copy command:/ });
      const displayed = command.textContent;
      assert.ok(displayed.includes(commandPart), `${platform}: expected install command`);

      for (let repeat = 0; repeat < 2; repeat++) {
        await user.click(active);
        for (const button of within(selector).getAllByRole("button")) {
          assert.equal(button.getAttribute("aria-pressed"), String(button === active));
        }
        assert.equal(screen.getByRole("heading", { level: 3, name: platform }).closest("article"), card);
        assert.equal(within(card).getByRole("button", { name: /^Copy command:/ }).textContent, displayed);
      }

      await user.click(command);
      const copied = await navigator.clipboard.readText();
      assert.ok(copied.includes(commandPart), `${platform}: copied command matches the displayed platform`);
      assert.ok(displayed.includes(copied), `${platform}: copied command matches the displayed command`);
    }
  } finally {
    cleanup();
  }
});

test("each platform renders and copies its exact installer staging command", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const expected = [
      ["macOS", 'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"'],
      ["Windows", `$Installer = Join-Path $env:TEMP ('phantom-install-${release.PUBLIC_RELEASE_TAG}-{0}.ps1' -f [Guid]::NewGuid().ToString('N'))`],
      ["Linux", 'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"'],
    ];
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    assert.equal(within(selector).getAllByRole("button").length, expected.length);
    for (const [platform, stagingLine] of expected) {
      await user.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card, `${platform}: install card is displayed`);
      const button = within(card).getByRole("button", { name: /^Copy command:/ });
      const commandNode = Array.from(button.firstElementChild.childNodes)
        .find((node) => node.nodeType === dom.window.Node.TEXT_NODE);
      assert.ok(commandNode, `${platform}: install command is rendered as text`);
      const displayed = commandNode.textContent;
      const stagingLines = displayed.split("\n").filter((line) =>
        platform === "Windows" ? line.startsWith("$Installer =") : line.startsWith("phantom_stage="),
      );
      assert.deepEqual(stagingLines, [stagingLine], `${platform}: exact displayed staging line`);
      await user.click(button);
      const copied = await navigator.clipboard.readText();
      assert.equal(copied, displayed, `${platform}: copied command matches rendered text`);
    }
  } finally {
    cleanup();
  }
});

test("both Unix examples stage and verify the current public installer before execution", async () => {
  const user = userEvent.setup();
  const source = `https://raw.githubusercontent.com/ashlrai/phantom-secrets/${release.PUBLIC_RELEASE_SOURCE_COMMIT}/scripts/install.sh`;
  render(React.createElement(QuickStart));
  try {
    for (const [platform, checksum] of [["macOS", "shasum -a 256 -c -"], ["Linux", "sha256sum -c -"]]) {
      await user.click(screen.getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      const button = within(card).getByRole("button", { name: /^Copy command:/ });
      const commandNode = Array.from(button.firstElementChild.childNodes)
        .find((node) => node.nodeType === dom.window.Node.TEXT_NODE);
      assert.ok(commandNode, `${platform}: command is displayed`);
      assert.equal(within(card).getByRole("link", { name: "View exact installer source" }).getAttribute("href"), source);
      const lines = commandNode.textContent.split("\n");
      const expected = [
        'phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"',
        'phantom_installer="$phantom_stage/install.sh"',
        `curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$phantom_installer" ${source}`,
        `printf '%s  %s\\n' ${release.PUBLIC_RELEASE_UNIX_INSTALLER_SHA256} "$phantom_installer" | ${checksum}`,
        'bash "$phantom_installer"',
      ];
      let previous = -1;
      for (const line of expected) {
        const index = lines.indexOf(line);
        assert.ok(index > previous, `${platform}: expected ordered line: ${line}`);
        assert.equal(lines.lastIndexOf(line), index, `${platform}: line occurs once`);
        previous = index;
      }
      await user.click(button);
      assert.equal(await navigator.clipboard.readText(), commandNode.textContent, `${platform}: copied command matches`);
    }
  } finally {
    cleanup();
  }
});

test("rendered and copied Unix install commands use the TMPDIR fallback and preserve special paths", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-rendered-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const tempPaths = [path.join(root, "temporary files"), path.join(root, "temporary[1]*")];
  // An unquoted template could expand to this existing path instead of TMPDIR.
  const decoy = path.join(root, "temporary1-decoy");
  const bin = path.join(root, "bin");
  const home = path.join(root, "home");
  const installedBin = path.join(home, ".phantom-secrets", "bin");
  const record = path.join(root, "stage-record");
  const checksumRecord = path.join(root, "checksum-record");
  const events = path.join(root, "events");
  for (const temp of tempPaths) fs.mkdirSync(temp);
  fs.mkdirSync(decoy);
  fs.writeFileSync(path.join(decoy, "phantom-install.XXXXXX"), "decoy");
  fs.mkdirSync(bin);
  fs.mkdirSync(installedBin, { recursive: true });
  const executable = (file, body) => fs.writeFileSync(file, `#!/bin/bash\n${body}\n`, { mode: 0o755 });
  for (const name of ["phantom", "phantom-mcp"]) executable(path.join(installedBin, name), "exit 0");
  executable(path.join(bin, "curl"), `
    while [[ $# -gt 0 && "$1" != "--output" ]]; do shift; done
    [[ $# -ge 2 ]] || exit 2
    printf '%s' "$2" > "$STAGE_RECORD"
    printf 'download\\n' >> "$EVENTS"
    printf '#!/bin/bash\\nprintf "execute:%%s\\n" "$0" >> "$EVENTS"\\n' > "$2"
  `);
  for (const name of ["shasum", "sha256sum"]) {
    executable(path.join(bin, name), 'cat > "$CHECKSUM_RECORD"; printf "checksum\\n" >> "$EVENTS"');
  }

  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    for (const platform of ["macOS", "Linux"]) {
      await user.click(screen.getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      const button = within(card).getByRole("button", { name: /^Copy command:/ });
      const commandNode = Array.from(button.firstElementChild.childNodes)
        .find((node) => node.nodeType === dom.window.Node.TEXT_NODE);
      assert.ok(commandNode, `${platform}: command is rendered as text`);
      const displayed = commandNode.textContent;
      await user.click(button);
      const copied = await navigator.clipboard.readText();
      assert.equal(copied, displayed, `${platform}: copied command matches rendered text`);
      for (const [label, temp, expectedParent] of [
        ["unset", undefined, "/tmp"],
        ["empty", "", "/tmp"],
        ...tempPaths.map((temp) => [path.basename(temp), temp, temp]),
      ]) {
        fs.rmSync(events, { force: true });
        const env = { HOME: home, PATH: `${bin}:/usr/bin:/bin`, STAGE_RECORD: record, CHECKSUM_RECORD: checksumRecord, EVENTS: events };
        if (temp !== undefined) env.TMPDIR = temp;
        const result = spawnSync("/bin/bash", ["-c", copied], {
          env,
          encoding: "utf8",
        });
        assert.equal(result.status, 0, `${platform}, ${label}: command failed: ${result.stderr}`);
        const installer = fs.readFileSync(record, "utf8");
        const stage = path.dirname(installer);
        assert.equal(path.dirname(stage), expectedParent, `${platform}, ${label}: staging directory parent`);
        assert.match(path.basename(stage), /^phantom-install\.[A-Za-z0-9]{6}$/, `${platform}, ${label}: mktemp template`);
        assert.equal(path.basename(installer), "install.sh");
        assert.equal(fs.readFileSync(checksumRecord, "utf8"), `${release.PUBLIC_RELEASE_UNIX_INSTALLER_SHA256}  ${installer}\n`, `${platform}, ${label}: verify the downloaded installer`);
        assert.equal(fs.readFileSync(events, "utf8"), `download\nchecksum\nexecute:${installer}\n`, `${platform}, ${label}: verify before executing the staged installer`);
        assert.equal(fs.existsSync(stage), false, `${platform}, ${label}: staging directory was cleaned up`);
        if (temp) assert.deepEqual(fs.readdirSync(temp), [], `${platform}: temporary path was cleaned up`);
      }
    }
    assert.equal(fs.readFileSync(path.join(decoy, "phantom-install.XXXXXX"), "utf8"), "decoy");
  } finally {
    cleanup();
  }
});

test("rendered Unix commands stop before downloading when TMPDIR does not exist", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-missing-temp-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const missingTemp = path.join(root, "missing directory");
  const bin = path.join(root, "bin");
  const downloadMarker = path.join(root, "download-started");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "curl"), '#!/bin/bash\ntouch "$DOWNLOAD_MARKER"\n', { mode: 0o755 });

  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    for (const platform of ["macOS", "Linux"]) {
      await user.click(screen.getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      const button = within(card).getByRole("button", { name: /^Copy command:/ });
      const commandNode = Array.from(button.firstElementChild.childNodes)
        .find((node) => node.nodeType === dom.window.Node.TEXT_NODE);
      assert.ok(commandNode, `${platform}: command is rendered as text`);
      assert.ok(commandNode.textContent.includes('${TMPDIR:-/tmp}/phantom-install.XXXXXX'));
      const result = spawnSync("/bin/bash", ["-c", commandNode.textContent], {
        env: { HOME: root, PATH: `${bin}:/usr/bin:/bin`, TMPDIR: missingTemp, DOWNLOAD_MARKER: downloadMarker },
        encoding: "utf8",
      });
      assert.equal(result.error, undefined, `${platform}: shell started`);
      assert.ok(Number.isInteger(result.status) && result.status !== 0, `${platform}: invalid TMPDIR must fail`);
      assert.equal(fs.existsSync(missingTemp), false, `${platform}: missing directory remains absent`);
      assert.equal(fs.existsSync(downloadMarker), false, `${platform}: download must not start`);
    }
  } finally {
    cleanup();
  }
});

test("displayed Linux install command creates a fresh private temporary directory on each run", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-linux-stage-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const temp = path.join(root, "temporary files");
  const bin = path.join(root, "bin");
  const home = path.join(root, "home");
  const installedBin = path.join(home, ".phantom-secrets", "bin");
  const record = path.join(root, "downloads.jsonl");
  fs.mkdirSync(temp);
  fs.mkdirSync(bin);
  fs.mkdirSync(installedBin, { recursive: true });
  const sentinel = path.join(temp, "install.sh");
  fs.writeFileSync(sentinel, "untouched");
  const executable = (file, body) => fs.writeFileSync(file, `#!/bin/bash\n${body}\n`, { mode: 0o755 });
  for (const name of ["phantom", "phantom-mcp"]) executable(path.join(installedBin, name), "exit 0");
  executable(path.join(bin, "sha256sum"), "cat >/dev/null");
  fs.writeFileSync(path.join(bin, "curl"), `#!${process.execPath}
const fs = require("node:fs");
const path = require("node:path");
const output = process.argv[process.argv.indexOf("--output") + 1];
const directory = path.dirname(output);
fs.appendFileSync(process.env.RECORD, JSON.stringify({ output, mode: fs.statSync(directory).mode & 0o777 }) + "\\n");
fs.writeFileSync(output, "#!/bin/bash\\nexit 0\\n");
`, { mode: 0o755 });

  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    await user.click(screen.getByRole("button", { name: "Linux" }));
    const card = screen.getByRole("heading", { level: 3, name: "Linux" }).closest("article");
    const button = within(card).getByRole("button", { name: /^Copy command:/ });
    const commandNode = Array.from(button.firstElementChild.childNodes)
      .find((node) => node.nodeType === dom.window.Node.TEXT_NODE);
    assert.ok(commandNode, "Linux command is displayed as text");
    for (let run = 0; run < 2; run++) {
      const result = spawnSync("/bin/bash", ["-c", commandNode.textContent], {
        env: { HOME: home, PATH: `${bin}:/usr/bin:/bin`, TMPDIR: temp, RECORD: record },
        encoding: "utf8",
      });
      assert.equal(result.status, 0, `run ${run + 1}: ${result.stderr}`);
    }
    const downloads = fs.readFileSync(record, "utf8").trim().split("\n").map(JSON.parse);
    assert.equal(downloads.length, 2);
    const stages = downloads.map(({ output, mode }) => {
      const stage = path.dirname(output);
      assert.equal(path.dirname(stage), temp);
      assert.match(path.basename(stage), /^phantom-install\.[A-Za-z0-9]{6}$/);
      assert.equal(path.basename(output), "install.sh");
      assert.equal(mode, 0o700, "staging directory is private");
      assert.equal(fs.existsSync(stage), false, "staging directory is cleaned up");
      return stage;
    });
    assert.notEqual(stages[0], stages[1], "each run uses a fresh staging directory");
    assert.equal(fs.readFileSync(sentinel, "utf8"), "untouched");
    assert.deepEqual(fs.readdirSync(temp), ["install.sh"]);
  } finally {
    cleanup();
  }
});

test("every displayed mktemp staging template has the Phantom prefix and random suffix", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    for (const [platform, expectedCount] of [["macOS", 1], ["Windows", 0], ["Linux", 1]]) {
      await user.click(screen.getByRole("button", { name: platform }));
      const commands = screen.getAllByRole("button", { name: /^Copy command:/ });
      const invocations = commands.flatMap((button) =>
        [...button.textContent.matchAll(/\bmktemp\b[^\n]*/g)].map((match) => match[0]),
      );
      assert.equal(invocations.length, expectedCount, `${platform}: displayed mktemp invocations`);
      for (const invocation of invocations) {
        assert.match(
          invocation,
          /^mktemp -d "\$\{TMPDIR:-\/tmp\}\/phantom-install\.X{6}"\)"$/,
          `${platform}: staging template includes the prefix and random suffix`,
        );
      }
    }
  } finally {
    cleanup();
  }
});

test("displayed QuickStart commands have no blank lines after staging directory creation", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    for (const [platform, expectedStages] of [["macOS", 1], ["Windows", 0], ["Linux", 1]]) {
      await user.click(screen.getByRole("button", { name: platform }));
      const buttons = screen.getAllByRole("button", { name: /^Copy command:/ });
      assert.equal(buttons.length, 3, `${platform}: all displayed commands are checked`);
      let stages = 0;
      for (const [index, button] of buttons.entries()) {
        const textNodes = Array.from(button.firstElementChild.childNodes)
          .filter((node) => node.nodeType === dom.window.Node.TEXT_NODE);
        assert.equal(textNodes.length, 1, `${platform}: command ${index + 1} is displayed as text`);
        const lines = textNodes[0].textContent.split("\n");
        for (const [lineIndex, line] of lines.entries()) {
          if (line.includes("mktemp -d")) {
            stages++;
            assert.ok(lines[lineIndex + 1]?.trim(), `${platform}: staging directory creation must be followed immediately by a command`);
          }
        }
      }
      assert.equal(stages, expectedStages, `${platform}: staging directory creation count`);
    }
  } finally {
    cleanup();
  }
});

test("each displayed installation command includes its temporary staging cleanup", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    const unixCleanup = `trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT`;
    const cases = [
      ["macOS", unixCleanup],
      ["Windows", "} finally {\n  Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue\n}"],
      ["Linux", unixCleanup],
    ];
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    assert.equal(within(selector).getAllByRole("button").length, cases.length);
    for (const [platform, cleanupCommand] of cases) {
      await user.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      const button = within(card).getByRole("button", { name: /^Copy command:/ });
      assert.ok(button.textContent.includes(cleanupCommand), `${platform}: displayed cleanup`);
      await user.click(button);
      const copied = await navigator.clipboard.readText();
      assert.ok(copied.includes(cleanupCommand), `${platform}: copied cleanup`);
    }
  } finally {
    cleanup();
  }
});

test("displayed Unix install commands quote every staging-directory reference", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    for (const platform of ["macOS", "Linux"]) {
      await user.click(screen.getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      const button = within(card).getByRole("button", { name: /^Copy command:/ });
      const command = Array.from(button.firstElementChild.childNodes)
        .find((node) => node.nodeType === dom.window.Node.TEXT_NODE).textContent;

      for (const required of [
        'mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX"',
        'phantom_installer="$phantom_stage/install.sh"',
        'rmdir -- "$phantom_stage"',
      ]) {
        assert.ok(command.includes(required), `${platform}: missing quoted staging reference: ${required}`);
      }
      // Strict textual allowlist of the current quoted forms, not a shell parser.
      const remaining = command.replace(/"(?:\$\{TMPDIR:-\/tmp\}\/phantom-install\.XXXXXX|\$phantom_stage\/install\.sh|\$phantom_stage|\$phantom_installer)"/g, "");
      assert.doesNotMatch(remaining, /\$(?:\{(?:TMPDIR|phantom_stage|phantom_installer)(?::-[^}]*)?\}|(?:TMPDIR|phantom_stage|phantom_installer)\b)/, `${platform}: staging reference outside reviewed quoted forms`);

      await user.click(button);
      assert.equal(await navigator.clipboard.readText(), command, `${platform}: copied command matches displayed text`);
    }
  } finally {
    cleanup();
  }
});

test("every displayed QuickStart command can be selected and matches the copied text", async () => {
  const style = document.createElement("style");
  style.textContent = fs.readFileSync(path.join(__dirname, "../src/app/globals.css"), "utf8");
  document.head.append(style);
  const user = userEvent.setup();
  try {
    render(React.createElement(QuickStart));
    for (const [platform, installPart] of [
      ["macOS", "shasum -a 256 -c -"],
      ["Windows", "Get-FileHash -Algorithm SHA256"],
      ["Linux", "sha256sum -c -"],
    ]) {
      await user.click(screen.getByRole("button", { name: platform }));
      const buttons = screen.getAllByRole("button", { name: /^Copy command:/ });
      assert.equal(buttons.length, 3, `${platform}: install and both follow-up commands are displayed`);
      for (const [index, button] of buttons.entries()) {
        const textContainer = button.firstElementChild;
        const textNodes = Array.from(textContainer.childNodes).filter((node) => node.nodeType === dom.window.Node.TEXT_NODE);
        assert.equal(textNodes.length, 1, `${platform}: command ${index + 1} is selectable text`);
        const command = textNodes[0].textContent;
        assert.ok(command, `${platform}: command ${index + 1} is not empty`);
        assert.equal(window.getComputedStyle(textContainer).userSelect, "text");
        assert.equal(window.getComputedStyle(textContainer).whiteSpace, "pre-wrap");
        if (index === 0) assert.ok(command.includes(installPart), `${platform}: expected installer`);
        if (index === 1) assert.equal(command, "phantom --version\nphantom-mcp --version");
        if (index === 2) assert.equal(command, "phantom init");

        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(textNodes[0]);
        selection.removeAllRanges();
        selection.addRange(range);
        assert.equal(selection.toString(), command, `${platform}: selection preserves the entire command`);
        await user.click(button);
        await waitFor(async () => assert.equal(await navigator.clipboard.readText(), command));
        selection.removeAllRanges();
      }
    }
  } finally {
    cleanup();
    style.remove();
  }
});

test("every displayed QuickStart command is nonempty and has no trailing whitespace", async () => {
  const user = userEvent.setup();
  render(React.createElement(QuickStart));
  try {
    for (const platform of ["macOS", "Windows", "Linux"]) {
      await user.click(screen.getByRole("button", { name: platform }));
      const buttons = screen.getAllByRole("button", { name: /^Copy command:/ });
      assert.equal(buttons.length, 3, `${platform}: install and both follow-up commands`);
      for (const [index, button] of buttons.entries()) {
        const commandNode = Array.from(button.firstElementChild.childNodes)
          .find((node) => node.nodeType === dom.window.Node.TEXT_NODE);
        assert.ok(commandNode, `${platform}: command ${index + 1} is displayed as text`);
        const command = commandNode.textContent;
        assert.ok(command.trim(), `${platform}: command ${index + 1} is nonempty`);
        for (const [lineIndex, line] of command.split("\n").entries()) {
          assert.doesNotMatch(line, /\s$/u, `${platform}: command ${index + 1}, line ${lineIndex + 1} has trailing whitespace`);
        }
      }
    }
  } finally {
    cleanup();
  }
});

test("switching platforms renders the selected multiline install snippet", async () => {
  const style = document.createElement("style");
  style.textContent = fs.readFileSync(path.join(__dirname, "../src/app/globals.css"), "utf8");
  document.head.append(style);
  const user = userEvent.setup();
  const snippets = {
    macOS: { lines: 12, opening: "(\nset -euo pipefail\numask 077", verification: "shasum -a 256 -c -", execution: "\nbash \"$phantom_installer\"\n", ending: '"$HOME/.phantom-secrets/bin/phantom-mcp" --version\n)' },
    Windows: { lines: 18, opening: "& {\n$ErrorActionPreference = 'Stop'\n$Installer =", verification: "Get-FileHash -Algorithm SHA256", execution: "\n  & $Installer\n", ending: "  Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue\n}\n}" },
    Linux: { lines: 12, opening: "(\nset -euo pipefail\numask 077", verification: "sha256sum -c -", execution: "\nbash \"$phantom_installer\"\n", ending: '"$HOME/.phantom-secrets/bin/phantom-mcp" --version\n)' },
  };
  try {
    render(React.createElement(QuickStart));
    const selector = screen.getByRole("group", { name: "Choose an operating system" });
    const seen = new Map();
    for (const platform of ["macOS", "Windows", "Linux", "macOS", "Windows"]) {
      await user.click(within(selector).getByRole("button", { name: platform }));
      const card = screen.getByRole("heading", { level: 3, name: platform }).closest("article");
      assert.ok(card);
      const button = within(card).getByRole("button", { name: /^Copy command:/ });
      const container = button.firstElementChild;
      const nodes = Array.from(container.childNodes).filter((node) => node.nodeType === dom.window.Node.TEXT_NODE);
      assert.equal(nodes.length, 1, `${platform}: snippet is visible text`);
      const snippet = nodes[0].textContent;
      const expected = snippets[platform];
      assert.ok(snippet.startsWith(expected.opening), `${platform}: opening lines`);
      assert.ok(snippet.includes(expected.verification), `${platform}: verification command`);
      assert.ok(snippet.includes(expected.execution), `${platform}: installer execution line`);
      assert.ok(snippet.endsWith(expected.ending), `${platform}: final lines`);
      assert.equal(snippet.split("\n").length, expected.lines, `${platform}: line breaks`);
      assert.equal(window.getComputedStyle(container).whiteSpace, "pre-wrap", `${platform}: line breaks are rendered`);
      for (const [other, value] of Object.entries(snippets)) {
        if (other !== platform) assert.ok(!snippet.includes(value.verification), `${platform}: no stale ${other} snippet`);
      }
      if (seen.has(platform)) assert.equal(snippet, seen.get(platform), `${platform}: switching back restores the snippet`);
      seen.set(platform, snippet);
      await user.click(button);
      await waitFor(async () => assert.equal(await navigator.clipboard.readText(), snippet));
    }
  } finally {
    cleanup();
    style.remove();
  }
});

test("QuickStart copy controls are named, reachable by Tab, and operable by keyboard", async () => {
  for (const platform of ["macOS", "Windows", "Linux"]) {
    const user = userEvent.setup();
    render(React.createElement(QuickStart));
    try {
      await user.click(screen.getByRole("button", { name: platform }));
      document.activeElement.blur();
      const buttons = screen.getAllByRole("button", { name: /^Copy command:/ });
      assert.equal(buttons.length, 3, `${platform}: selected platform and setup steps have named copy buttons`);
      assert.equal(screen.getByRole("button", { name: "Copy command: phantom init" }), buttons[2]);

      const commandNode = Array.from(buttons[0].firstElementChild.childNodes)
        .find((node) => node.nodeType === dom.window.Node.TEXT_NODE);
      assert.ok(commandNode, `${platform}: install command is text`);
      const range = document.createRange();
      range.selectNodeContents(commandNode);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      const selectedCommand = selection.toString();
      assert.ok(selectedCommand.includes("\n"), `${platform}: selection includes line breaks`);
      await user.click(buttons[0]);
      await waitFor(async () => assert.equal(await navigator.clipboard.readText(), selectedCommand));
      selection.removeAllRanges();
      document.activeElement.blur();

      const reached = [];
      for (let i = 0; i < 40 && reached.length < buttons.length; i++) {
        await user.tab();
        if (buttons.includes(document.activeElement)) reached.push(document.activeElement);
      }
      assert.deepEqual(reached, buttons, `${platform}: Tab reaches every copy button in document order`);

      for (const key of ["{Enter}", " "]) {
        await navigator.clipboard.writeText("");
        await user.keyboard(key);
        await waitFor(async () => assert.equal(await navigator.clipboard.readText(), "phantom init"));
        assert.equal(document.activeElement, buttons[2], "copying keeps focus on the control");
      }
    } finally {
      cleanup();
    }
  }
});
