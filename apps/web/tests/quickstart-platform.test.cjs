const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

function load(relativePath, localRequire = require) {
  const source = fs.readFileSync(path.join(__dirname, "..", relativePath), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, localRequire);
  return exports;
}

function findElements(element, predicate) {
  if (!React.isValidElement(element)) return [];
  return [
    ...(predicate(element) ? [element] : []),
    ...React.Children.toArray(element.props.children).flatMap((child) => findElements(child, predicate)),
  ];
}

function assertStagingOrder(platform, command) {
  const unix = platform !== "Windows";
  const creation = unix
    ? /^\s*phantom_stage="\$\(mktemp -d [^\n]+\)"/m.exec(command)
    : /^\s*\$Installer\s*=\s*Join-Path\s+\$env:TEMP\b[^\n]*/mi.exec(command);
  assert.ok(creation, `${platform}: staging location is created or assigned`);
  const assignmentEnd = creation.index + creation[0].length;
  const variableIndex = unix ? 0 : creation.index + creation[0].search(/\$Installer\b/i);
  const use = unix
    ? /\$(?:phantom_stage\b|\{phantom_stage\})/.exec(command)
    : /\$Installer\b/i.exec(command.slice(variableIndex + "$Installer".length));
  assert.ok(use, `${platform}: staging location is used`);
  if (unix) {
    assert.ok(assignmentEnd <= use.index, `${platform}: staging directory must exist before its first use`);
  } else {
    // The assignment is the first occurrence of the installer variable.
    assert.equal(command.search(/\$Installer\b/i), variableIndex,
      `${platform}: temporary installer path must be assigned before its first use`);
    assert.ok(variableIndex + "$Installer".length + use.index >= assignmentEnd,
      `${platform}: temporary installer path must be assigned before its first use`);
  }
}

test("displayed install commands create or assign staging locations before first use", () => {
  let selected = "macOS";
  const hooks = { ...React, useState() { return [selected, (value) => { selected = value; }]; } };
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return hooks;
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });

  const platforms = findElements(QuickStart(), (element) => element.type === "button")
    .map((button) => button.props.children);
  assert.deepEqual(platforms, ["macOS", "Windows", "Linux"]);
  for (const platform of platforms) {
    selected = platform;
    const cards = findElements(QuickStart(), (element) => element.type === "article");
    assert.equal(cards.length, 1, `${platform}: one displayed install card`);
    const commands = findElements(cards[0], (element) => typeof element.props.text === "string");
    assert.equal(commands.length, 1, `${platform}: one displayed install command`);
    assertStagingOrder(platform, commands[0].props.text);
  }
});

test("staging order check rejects missing creation and use before creation", () => {
  const unix = 'phantom_stage="$(mktemp -d /tmp/phantom-install.XXXXXX)"\nphantom_installer="$phantom_stage/install.sh"';
  const windows = '$Installer = Join-Path $env:TEMP "installer.ps1"\nInvoke-WebRequest -OutFile $Installer';
  for (const [platform, command, prematureUse] of [
    ["macOS", unix, 'echo "$phantom_stage"'],
    ["Linux", unix, 'echo "${phantom_stage}"'],
    ["Windows", windows, 'Write-Output $Installer'],
  ]) {
    assertStagingOrder(platform, command);
    assert.throws(() => assertStagingOrder(platform, `${prematureUse}\n${command}`), /before its first use/);
    assert.throws(() => assertStagingOrder(platform, command.split("\n").slice(1).join("\n")), /staging location is created or assigned/);
  }
  assert.throws(() => assertStagingOrder("Windows", windows.replace('"installer.ps1"', '$Installer')), /before its first use/);
});

test("switching platforms displays the selected install instructions", () => {
  let selected;
  const hooks = { ...React, useState(initial) { selected ??= initial; return [selected, (value) => { selected = value; }]; } };
  const release = load("src/lib/public-release.ts");
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return hooks;
    if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
    if (name === "@/lib/public-release") return release;
    if (name === "./CopyButton") return { CopyButton: ({ text }) => React.createElement("pre", null, text) };
    return require(name);
  });

  const cases = [
    { name: "macOS", command: "shasum -a 256 -c -", asset: "phantom-aarch64-apple-darwin.tar.gz", caveat: "The release is not notarized" },
    { name: "Windows", command: "Get-FileHash -Algorithm SHA256", asset: "phantom-aarch64-pc-windows-msvc.zip", caveat: "Windows archives are not Authenticode-signed" },
    { name: "Linux", command: "sha256sum -c -", asset: "phantom-aarch64-unknown-linux-gnu.tar.gz", caveat: "The default keyutils vault is session-persistent" },
    { name: "macOS", command: "shasum -a 256 -c -", asset: "phantom-aarch64-apple-darwin.tar.gz", caveat: "The release is not notarized" },
  ];

  for (const [index, expected] of cases.entries()) {
    if (index > 0) {
      const buttons = findElements(QuickStart(), (element) => element.type === "button");
      const button = buttons.find((element) => element.props.children === expected.name);
      assert.ok(button, `selector for ${expected.name}`);
      button.props.onClick();
    }
    const tree = QuickStart();
    const buttons = findElements(tree, (element) => element.type === "button");
    assert.equal(buttons.length, 3);
    for (const button of buttons) assert.equal(button.props["aria-pressed"], button.props.children === expected.name);
    const html = renderToStaticMarkup(tree);
    assert.match(html, new RegExp(`<h3>${expected.name}</h3>`));
    for (const other of cases.filter((item) => item.name !== expected.name)) {
      assert.ok(!html.includes(`<h3>${other.name}</h3>`));
      assert.ok(!html.includes(other.asset));
    }
    for (const content of [expected.command, expected.asset, expected.caveat]) assert.ok(html.includes(content), content);
  }
});

test("each Unix install command chooses a staging template when TMPDIR is unset or empty", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-quickstart-template-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  const record = path.join(root, "mktemp-args");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "mktemp"), '#!/bin/bash\nprintf "%s\\n" "$@" > "$ARG_RECORD"\nexit 42\n', { mode: 0o755 });

  let selected = "macOS";
  const hooks = { ...React, useState() { return [selected, (value) => { selected = value; }]; } };
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return hooks;
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });

  for (const platform of ["macOS", "Linux"]) {
    selected = platform;
    const card = findElements(QuickStart(), (element) => element.type === "article")[0];
    const commands = findElements(card, (element) => typeof element.props.text === "string");
    assert.equal(commands.length, 1, `${platform}: one displayed install command`);
    for (const [label, tmpdir, expected] of [
      ["unset", undefined, "/tmp"],
      ["empty", "", "/tmp"],
      ["override with spaces", path.join(root, "temp with spaces"), path.join(root, "temp with spaces")],
    ]) {
      fs.rmSync(record, { force: true });
      const env = { PATH: `${bin}:/usr/bin:/bin`, ARG_RECORD: record };
      if (tmpdir !== undefined) env.TMPDIR = tmpdir;
      const result = spawnSync("/bin/bash", ["-c", commands[0].props.text], { env, encoding: "utf8" });
      assert.equal(result.status, 42, `${platform}, ${label}: expected the mktemp stub to stop the command`);
      assert.equal(fs.readFileSync(record, "utf8"), `-d\n${expected}/phantom-install.XXXXXX\n`, `${platform}, ${label}`);
    }
  }
});

test("Unix install commands clean their staging directory on success and failure", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-quickstart-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  const home = path.join(root, "home");
  const temp = path.join(root, "temp with spaces");
  fs.mkdirSync(bin);
  fs.mkdirSync(temp);
  const installedBin = path.join(home, ".phantom-secrets", "bin");
  fs.mkdirSync(installedBin, { recursive: true });
  const executable = (file, contents) => fs.writeFileSync(file, `#!/bin/bash\n${contents}\n`, { mode: 0o755 });
  for (const name of ["phantom", "phantom-mcp"]) executable(path.join(installedBin, name), "exit 0");
  executable(path.join(bin, "curl"), `
    while [[ $# -gt 0 && "$1" != "--output" ]]; do shift; done
    [[ $# -ge 2 ]] || exit 2
    installer="$2"
    printf '%s' "$(dirname "$installer")" > "$STAGE_RECORD"
    printf '#!/bin/bash\\n[[ "$FAIL_POINT" != installer ]]\\n' > "$installer"
    if [[ "$FAIL_POINT" == nonempty ]]; then touch "$(dirname "$installer")/extra"; fi
    [[ "$FAIL_POINT" != download ]]
  `);
  for (const name of ["shasum", "sha256sum"]) {
    executable(path.join(bin, name), 'cat >/dev/null; [[ "$FAIL_POINT" != checksum ]]');
  }

  let selected = "macOS";
  const hooks = { ...React, useState() { return [selected, (value) => { selected = value; }]; } };
  const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
    if (name === "react") return hooks;
    if (name === "next/link") return { __esModule: true, default: () => null };
    if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
    if (name === "./CopyButton") return { CopyButton: () => null };
    return require(name);
  });

  for (const platform of ["macOS", "Linux"]) {
    selected = platform;
    const command = findElements(QuickStart(), (element) => typeof element.props.text === "string")
      .find((element) => element.props.text.includes("mktemp -d")).props.text;
    for (const failure of ["", "download", "checksum", "installer", "nonempty", "default-temp", "unset-temp"]) {
      const record = path.join(root, "stage-record");
      const env = { HOME: home, PATH: `${bin}:/usr/bin:/bin`, FAIL_POINT: failure, STAGE_RECORD: record };
      if (failure !== "unset-temp") env.TMPDIR = failure === "default-temp" ? "" : temp;
      const result = spawnSync("/bin/bash", ["-c", command], {
        env,
        encoding: "utf8",
      });
      assert.equal(result.status, ["download", "checksum", "installer"].includes(failure) ? 1 : 0, `${platform}: ${failure || "success"}: ${result.stderr}`);
      const stage = fs.readFileSync(record, "utf8");
      assert.equal(path.dirname(stage), ["default-temp", "unset-temp"].includes(failure) ? "/tmp" : temp);
      assert.match(path.basename(stage), /^phantom-install\.[A-Za-z0-9]{6}$/, `${platform}: staging directory prefix`);
      if (failure === "nonempty") {
        assert.deepEqual(fs.readdirSync(stage), ["extra"], "cleanup must leave a nonempty directory without the installer");
        fs.rmSync(stage, { recursive: true });
      } else {
        assert.equal(fs.existsSync(stage), false, `${platform}: ${failure || "success"} left its staging directory`);
      }
      assert.deepEqual(fs.readdirSync(temp), [], `${platform}: ${failure || "success"} left staging files`);
    }
  }
});

test("internal notes describe the displayed installer staging override", () => {
  const notes = fs.readFileSync(path.join(__dirname, "../../../docs/internal/notes.md"), "utf8");
  assert.ok(notes.includes('mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX"'));
  assert.match(notes, /Set and export `TMPDIR`\s+to an existing writable directory/);
  assert.match(notes, /`TMPDIR` is unset or empty, the shell falls back to `\/tmp`/);
  assert.match(notes, /After the exit trap is installed, it attempts to remove the installer and then\s+the empty staging directory on exit, including on failure/);
  assert.match(notes, /Windows instead uses a\s+temporary installer file under PowerShell's `\$env:TEMP`/);
});

test("public installation guide describes the landing command's staging cleanup", () => {
  const guide = fs.readFileSync(path.join(__dirname, "../../../docs/getting-started.md"), "utf8");
  assert.match(guide, /landing page\]\(https:\/\/phm\.dev\/#install\)/);
  assert.match(guide, /under `TMPDIR`, or\s+`\/tmp` when `TMPDIR` is unset or empty/);
  assert.match(guide, /Once the exit trap is installed, it attempts to\s+remove the script and then the directory on exit, including after a command\s+fails/);
  assert.match(guide, /directory is removed only if it is empty; cleanup can fail and is\s+not guaranteed/);
  assert.match(guide, /not the\s+manual archive steps below/);
});
