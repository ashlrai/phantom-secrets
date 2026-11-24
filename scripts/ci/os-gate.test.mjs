import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { annotation, firstFailure, summarize } from "./first-failure.mjs";
import { decide } from "./os-gate.mjs";

const CI = readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");

test("an OS gate passes success and path-gate skips", () => {
    assert.deepEqual(decide({
        lint: { result: "success" },
        "install-smoke-linux": { result: "skipped" },
    }), { ok: true, bad: [] });
});

test("an OS gate fails on failure or cancellation", () => {
    const failed = decide({ "affected-windows": { result: "failure" } });
    assert.equal(failed.ok, false);
    assert.deepEqual(failed.bad, ["affected-windows=failure"]);
    assert.equal(decide({ "install-smoke-macos": { result: "cancelled" } }).ok, false);
});

test("the first failure keeps file and line", () => {
    const text = "error: could not compile\n --> crates/phantom-cli/src/main.rs:12:5\n";
    const hit = firstFailure(text);
    assert.equal(hit.file, "crates/phantom-cli/src/main.rs");
    assert.equal(hit.line, "12");
    const summary = summarize(text, 1);
    assert.match(summary.markdown, /main\.rs:12/);
    assert.equal(annotation(summary), "::error file=crates/phantom-cli/src/main.rs,line=12::build failed");
    assert.equal(annotation(summarize("cargo: command not found\n", 127)), "::error::build failed");
});

test("OS gates are not CI Gate needs and the check names are exact", () => {
    const gate = CI.slice(CI.indexOf("\n  gate:\n"), CI.indexOf("\n  fixup-queue:\n"));
    for (const name of ["Gate (linux)", "Gate (windows)", "Gate (macos)",
        "install smoke (linux)", "install smoke (windows)", "install smoke (macos)"]) {
        assert.match(CI, new RegExp(`name: ${name.replace(/[()]/g, "\\$&")}`));
        assert.doesNotMatch(gate, new RegExp(name));
    }
    for (const id of ["affected-windows", "affected-macos", "install-smoke-linux",
        "install-smoke-windows", "install-smoke-macos", "gate-linux", "gate-windows", "gate-macos"]) {
        assert.doesNotMatch(gate, new RegExp(`\\b${id}\\b`));
    }
    assert.equal(CI.includes("secrets."), false);
});

test("install smoke runs the documented commands and not npm install", () => {
    const script = readFileSync(new URL("./install-smoke.sh", import.meta.url), "utf8");
    assert.match(script, /cargo install --path crates\/phantom-cli/);
    assert.match(script, /--help/);
    assert.match(script, /init --empty/);
    assert.match(script, /init\)/);
    assert.doesNotMatch(script, /^[^#]*npm /m);
    const bin = "/tmp/phantom-smoke-stub";
    spawnSync("bash", ["-c", `cat > ${bin} <<'EOF'
#!/bin/bash
if [ "$1" = "--help" ]; then exit 0; fi
if [ "$1" = "init" ]; then exit 0; fi
exit 1
EOF
chmod +x ${bin}`]);
    const sourced = spawnSync("bash", ["-c", `
      source scripts/ci/install-smoke.sh
      smoke_commands ${bin}
    `], { encoding: "utf8" });
    assert.equal(sourced.status, 0, sourced.stderr);
});
