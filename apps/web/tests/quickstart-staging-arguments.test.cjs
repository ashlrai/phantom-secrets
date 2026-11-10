const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const React = require("react");
const ts = require("typescript");

function load(file, localRequire = require) {
  const source = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", compiled)(exports, localRequire);
  return exports;
}

function find(element, predicate) {
  if (!React.isValidElement(element)) return [];
  return [
    ...(predicate(element) ? [element] : []),
    ...React.Children.toArray(element.props.children).flatMap((child) => find(child, predicate)),
  ];
}

let selected = "macOS";
const { QuickStart } = load("src/components/landing/QuickStart.tsx", (name) => {
  if (name === "react") return { ...React, useState: () => [selected, () => {}] };
  if (name === "next/link") return { __esModule: true, default: () => null };
  if (name === "@/lib/public-release") return load("src/lib/public-release.ts");
  if (name === "./CopyButton") return { CopyButton: () => null };
  return require(name);
});
const release = load("src/lib/public-release.ts");

test("each displayed Unix staging command passes the created path intact", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "quickstart-arguments-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  const home = path.join(root, "home");
  const temp = path.join(root, "temporary files");
  const stage = path.join(temp, "created directory with spaces");
  const log = path.join(root, "events");
  const installed = path.join(home, ".phantom-secrets", "bin");
  for (const dir of [bin, temp, installed]) fs.mkdirSync(dir, { recursive: true });
  const stub = (name, body) => fs.writeFileSync(path.join(bin, name), `#!/bin/bash\nset -eu\n${body}\n`, { mode: 0o755 });
  stub("mktemp", '[ "$#" -eq 2 ] && [ "$1" = -d ] && [ "$2" = "$TMPDIR/phantom-install.XXXXXX" ]\n/bin/mkdir "$STAGE"\nprintf "%s\\n" "$STAGE"');
  stub("curl", `while [ "$#" -gt 0 ] && [ "$1" != --output ]; do shift; done
[ "$#" -eq 3 ] && [ "$2" = "$STAGE/install.sh" ]
printf 'download\\n' >> "$LOG"
printf '#!/bin/bash\\nset -e\\n[ "$#" -eq 0 ] && [ "$0" = "$STAGE/install.sh" ]\\nprintf "execute\\\\n" >> "$LOG"\\n' > "$2"`);
  for (const name of ["shasum", "sha256sum"]) {
    stub(name, 'IFS= read -r line\n[ "$line" = "$DIGEST  $STAGE/install.sh" ]\nprintf "verify\\n" >> "$LOG"');
  }
  stub("rm", '[ "$#" -eq 3 ] && [ "$1" = -f ] && [ "$2" = -- ] && [ "$3" = "$STAGE/install.sh" ]\nprintf "remove installer\\n" >> "$LOG"\n/bin/rm "$@"');
  stub("rmdir", '[ "$#" -eq 2 ] && [ "$1" = -- ] && [ "$2" = "$STAGE" ]\nprintf "remove directory\\n" >> "$LOG"\n/bin/rmdir "$@"');
  for (const name of ["phantom", "phantom-mcp"]) {
    fs.writeFileSync(path.join(installed, `.${name}-stub`), "#!/bin/bash\nexit 0\n", { mode: 0o755 });
    fs.symlinkSync(`.${name}-stub`, path.join(installed, name));
  }

  for (const platform of ["macOS", "Linux"]) {
    selected = platform;
    const command = find(QuickStart(), (node) => typeof node.props.text === "string")[0].props.text;
    fs.writeFileSync(log, "");
    const result = spawnSync("/bin/bash", ["-c", command], {
      env: { HOME: home, PATH: `${bin}:/usr/bin:/bin`, TMPDIR: temp, STAGE: stage, LOG: log,
        DIGEST: release.PUBLIC_RELEASE_UNIX_INSTALLER_SHA256 },
      encoding: "utf8", timeout: 30000,
    });
    assert.equal(result.status, 0, `${platform}: ${result.stderr}`);
    assert.equal(fs.readFileSync(log, "utf8"), "download\nverify\nexecute\nremove installer\nremove directory\n", platform);
    assert.equal(fs.existsSync(stage), false, `${platform}: directory removed`);
  }
});
