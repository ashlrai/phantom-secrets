import assert from "node:assert/strict";
import test from "node:test";
import { annotation, firstFailure, summarize } from "./nextest-summary.mjs";

const sample = `
        FAIL [   0.093s] phantom-secrets::versioned_json_test env_json_reports_counts
    test env_json_reports_counts ... FAILED
thread 'env_json_reports_counts' panicked at crates/phantom-cli/tests/versioned_json_test.rs:21:5:
assertion failed: output.stderr.is_empty()
`;

test("first failing test keeps file and line and drops the rest of the log", () => {
    const hit = firstFailure(sample);
    assert.equal(hit.file, "crates/phantom-cli/tests/versioned_json_test.rs");
    assert.equal(hit.line, "21");
    assert.equal(hit.name, "env_json_reports_counts");
    const summary = summarize(sample, 1);
    assert.equal(summary.ok, false);
    assert.match(summary.markdown, /versioned_json_test\.rs:21/);
    assert.doesNotMatch(summary.markdown, /assertion failed/);
});

test("a green run has an empty failure", () => {
    const summary = summarize("passed\n", 0);
    assert.equal(summary.ok, true);
    assert.equal(annotation(summary), "");
});

test("a missing location does not emit a broken annotation", () => {
    const summary = summarize("cargo: command not found\n", 127);
    assert.equal(summary.file, "");
    assert.equal(summary.line, "");
    assert.match(summary.markdown, /command not found/);
    assert.doesNotMatch(summary.markdown, /cargo: command not found[\s\S]*cargo: command not found/);
    assert.equal(annotation(summary), "::error::affected test failed");
});

test("a located failure annotates file and line", () => {
    const summary = summarize(sample, 1);
    assert.equal(
        annotation(summary),
        "::error file=crates/phantom-cli/tests/versioned_json_test.rs,line=21::env_json_reports_counts",
    );
});
