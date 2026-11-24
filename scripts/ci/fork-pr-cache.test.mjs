// Fork pull requests get a read-only GITHUB_TOKEN and may not be allowed to
// write the Actions cache. A denied cache write must not fail CI Gate.
// The checks themselves still run; only the save is optional.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const CI = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "..", ".github", "workflows", "ci.yml"),
    "utf8",
);

function stepBlock(name) {
    const at = CI.indexOf(`- name: ${name}\n`);
    assert.notEqual(at, -1, `step ${name} missing`);
    const next = CI.indexOf("\n      - ", at + 1);
    return CI.slice(at, next === -1 ? at + 800 : next);
}

test("verified tool caches are not saved on pull_request and a denied write does not fail the job", () => {
    for (const name of ["Save verified cargo-deny archive", "Save verified gitleaks archive"]) {
        const block = stepBlock(name);
        assert.match(block, /github\.event_name != 'pull_request'/, name);
        assert.match(block, /continue-on-error: true/, name);
        assert.match(block, /uses: actions\/cache\/save@0057852bfaa89a56745cba8c7296529d2fc39830/, name);
    }
});

test("Lint does not save the Rust cache on a pull request", () => {
    const lint = CI.slice(CI.indexOf("\n  lint:\n"), CI.indexOf("\n  dependency-policy:\n"));
    assert.match(lint, /Swatinem\/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32/);
    assert.match(lint, /save-if: \$\{\{ github\.event_name != 'pull_request' \}\}/);
});

test("pull request classification does not run cargo metadata for an unused filterset", () => {
    const changes = CI.slice(CI.indexOf("\n  changes:\n"), CI.indexOf("\n  test:\n"));
    assert.doesNotMatch(changes, /affected-filterset\.sh/);
    assert.match(changes, /filterset=all\(\)/);
});

test("CI Gate still reports on every pull request and merge_group", () => {
    assert.match(CI, /\n  merge_group:\n/);
    assert.doesNotMatch(CI, /pull_request:[\s\S]{0,200}paths:/);
    assert.match(CI, /\n  gate:\n    name: CI Gate\n    if: always\(\)/);
    assert.equal(CI.includes("secrets."), false);
});
