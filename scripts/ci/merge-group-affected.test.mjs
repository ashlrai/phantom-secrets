import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

// merge_group must run the same affected-only checks as pull_request. The
// full nextest profile, coverage tooling and the coverage job are limited to
// schedule and workflow_dispatch (nightly-full.yml calls ci.yml, so the
// caller's event_name is one of those two).
const HERE = dirname(fileURLToPath(import.meta.url));
const CI = readFileSync(join(HERE, "..", "..", ".github", "workflows", "ci.yml"), "utf8");
const FULL_ONLY = "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')";

const stepIf = (name) => {
    const at = CI.indexOf(`- name: ${name}\n`);
    assert.notEqual(at, -1, `step ${name} missing`);
    const m = /\n\s+if: (.*)/.exec(CI.slice(at, at + 600));
    assert.ok(m, `step ${name} has no if`);
    return m[1];
};

describe("merge_group is affected-only", () => {
    test("coverage steps run only on schedule and workflow_dispatch", () => {
        for (const name of ["Install coverage tools", "Install cargo-llvm-cov", "Run tests with coverage", "Upload coverage report"]) {
            const cond = stepIf(name);
            assert.ok(cond.includes(FULL_ONLY), `${name}: ${cond}`);
            assert.ok(!cond.includes("merge_group"), `${name} mentions merge_group`);
        }
    });

    test("filterset Run tests step is the path for every non-full event", () => {
        const cond = stepIf("Run tests");
        assert.ok(cond.includes("github.event_name != 'schedule' && github.event_name != 'workflow_dispatch'"), cond);
        assert.ok(!cond.includes("merge_group"), cond);
    });

    test("coverage job is not selected by merge_group", () => {
        const job = /\n  coverage:\n[\s\S]*?\n    runs-on:/.exec(CI)?.[0] ?? "";
        const cond = /\n    if: (.*)/.exec(job)?.[1] ?? "";
        assert.ok(cond.includes(FULL_ONLY), cond);
        assert.ok(cond.includes("inputs.validation_scope != 'windows-native-diagnostics'"), cond);
        assert.ok(!cond.includes("merge_group"), cond);
    });

    test("CI Gate still reports on merge_group and expects daily-only jobs skipped", () => {
        assert.match(CI, /\n  merge_group:/);
        assert.match(CI, /const full = process\.env\.EVENT !== 'pull_request' && process\.env\.EVENT !== 'merge_group';/);
        assert.match(CI, /\n  gate:\n    name: CI Gate\n    if: always\(\)/);
    });
});
