// Read-only contract over .github/workflows/{ci,codeql,nightly-full}.yml.
//
// Reworks #562 on the post-RQ-CI-SECONDS workflow shape. #562 tried to take
// the macOS/Windows test legs and Rust CodeQL analysis off the pull_request
// path for runner capacity; main went further — PRs and the merge queue now
// run only the seconds-fast checks, the full matrix is daily-only via
// nightly-full.yml, and CodeQL fans out per-language from the diff. This
// suite locks that split so no heavy job can silently reattach to the PR or
// merge-queue path, no `push` trigger can regrow a per-push matrix, the
// CodeQL matrix stays diff-scoped on PRs, and `CI Gate` can never be left
// pending by a missing job.
//
// The extractor is deliberately minimal: it understands exactly the job `if`
// shapes this repo writes (event_name equality/inequality, always(),
// needs.<job>.result == 'success'), split on top-level && / ||. An `if` shape
// it cannot read fails loud, never silently permissive. It writes nothing.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { ALL_OSES } from "./daily-matrix.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const wf = (name) =>
    readFileSync(join(repoRoot, ".github", "workflows", name), "utf8");
const ci = wf("ci.yml");
const codeql = wf("codeql.yml");
const nightly = wf("nightly-full.yml");

// ---------------------------------------------------------------------------
// Minimal workflow surface extractor

// The `key:` top-level block, captured until the next column-0 line.
function topBlock(yaml, key) {
    const m = new RegExp(`^${key}:\\s*\\n`, "m").exec(yaml);
    if (!m) return "";
    const rest = yaml.slice(m.index + m[0].length);
    const end = rest.search(/^[^\s#]/m);
    return end === -1 ? rest : rest.slice(0, end);
}

// jobs: -> Map<jobId, {if, needs}>. Job ids sit at two-space indent, their
// `if:`/`needs:` props at four; everything else is ignored.
function jobMap(yaml) {
    const jobs = new Map();
    let cur = null;
    for (const line of topBlock(yaml, "jobs").split("\n")) {
        const jm = line.match(/^  ([A-Za-z0-9_-]+):\s*$/);
        if (jm) {
            cur = jm[1];
            jobs.set(cur, { if: null, needs: [] });
            continue;
        }
        if (!cur) continue;
        const im = line.match(/^    if:\s*(.+?)\s*$/);
        if (im) jobs.get(cur).if = im[1];
        const nl = line.match(/^    needs:\s*\[([^\]]*)\]/);
        if (nl) jobs.get(cur).needs = nl[1].split(",").map((s) => s.trim()).filter(Boolean);
        const ns = line.match(/^    needs:\s*([A-Za-z0-9_-]+)\s*$/);
        if (ns) jobs.get(cur).needs = [ns[1]];
    }
    return jobs;
}

// Split expr on `op` at parenthesis depth 0.
function splitTop(expr, op) {
    const parts = [];
    let depth = 0;
    let start = 0;
    for (let i = 0; i < expr.length; i += 1) {
        const c = expr[i];
        if (c === "(") depth += 1;
        else if (c === ")") depth -= 1;
        else if (depth === 0 && expr.startsWith(op, i)) {
            parts.push(expr.slice(start, i));
            i += op.length - 1;
            start = i + 1;
        }
    }
    parts.push(expr.slice(start));
    return parts.map((s) => s.trim()).filter(Boolean);
}

const stripExpr = (s) => s.replace(/^\$\{\{\s*/, "").replace(/\s*\}\}\s*$/, "");

// Can this ||-disjunct hold on `event`? Positive event bindings must include
// it, an explicit != excludes it, and a needs.<job>.result == 'success'
// reference requires <job> to be runnable on it.
function disjunctPossible(d, event, runnable) {
    if (new RegExp(`github\\.event_name\\s*!=\\s*'${event}'`).test(d)) return false;
    const bound = [...d.matchAll(/github\.event_name\s*==\s*'([^']+)'/g)].map((m) => m[1]);
    if (bound.length && !bound.includes(event)) return false;
    for (const m of d.matchAll(/needs\.([A-Za-z0-9_-]+)\.result\s*==\s*'success'/g)) {
        if (!runnable.get(m[1])) return false;
    }
    return true;
}

function ifPossibleOn(jobIf, event, runnable) {
    if (jobIf === null) return true;
    return splitTop(stripExpr(jobIf), "&&").every((c) =>
        splitTop(c.replace(/^\(|\)$/g, ""), "||").some((d) =>
            disjunctPossible(d, event, runnable),
        ),
    );
}

// Fixed-point over the job graph: a job runs on `event` iff its `if` can hold
// and (unless the `if` is always()-gated) every need can run. Needs can only
// ever remove runnability, so iterating to a fixpoint converges.
function runnableSet(jobs, event) {
    const runnable = new Map([...jobs.keys()].map((k) => [k, true]));
    for (let pass = 0; pass <= jobs.size; pass += 1) {
        let changed = false;
        for (const [id, j] of jobs) {
            const deps =
                /always\(\)/.test(j.if ?? "") ||
                j.needs.every((n) => runnable.get(n) !== false);
            const v = ifPossibleOn(j.if, event, runnable) && deps;
            if (v !== runnable.get(id)) {
                runnable.set(id, v);
                changed = true;
            }
        }
        if (!changed) break;
    }
    return new Set([...runnable.entries()].filter(([, v]) => v).map(([k]) => k));
}

const ciJobs = jobMap(ci);
const codeqlJobs = jobMap(codeql);

// The seconds-fast set every pull_request and merge_group run executes.
const FAST_SET = new Set([
    "changes",
    "dependency-policy",
    "gate",
    "lint",
    "npm-wrappers",
    "secret-scan",
    "secret-shape",
]);

// ---------------------------------------------------------------------------
// ci.yml triggers: PR + merge queue only; the matrix lives on the daily cron

test("ci.yml has no push trigger — the heavy matrix cannot regrow per-push", () => {
    const on = topBlock(ci, "on");
    for (const t of ["pull_request", "merge_group", "workflow_dispatch", "workflow_call"]) {
        assert.match(on, new RegExp(`^  ${t}:`, "m"), `missing ${t} trigger`);
    }
    assert.doesNotMatch(on, /^  push:/m);
});

test("pull_request and merge_group run only the seconds-fast job set", () => {
    for (const event of ["pull_request", "merge_group"]) {
        assert.deepEqual(
            runnableSet(ciJobs, event),
            FAST_SET,
            `${event} job set drifted — a heavy job reattached or a fast job was lost`,
        );
    }
});

test("the daily schedule and dispatch still run the complete matrix", () => {
    const all = new Set(ciJobs.keys());
    // coverage uploads only happen on merge_group/schedule; everything else,
    // including the dispatch-only Ignored Tests leg, runs on dispatch.
    assert.deepEqual(
        runnableSet(ciJobs, "workflow_dispatch"),
        new Set([...all].filter((j) => j !== "coverage")),
    );
    // Every job except the dispatch-only Ignored Tests leg.
    assert.deepEqual(
        runnableSet(ciJobs, "schedule"),
        new Set([...all].filter((j) => j !== "test-ignored")),
    );
    // A bare workflow_call (event_name = 'workflow_call') runs the matrix but
    // not the schedule/dispatch-only jobs (coverage upload, fixup queue,
    // ignored tests).
    assert.deepEqual(
        runnableSet(ciJobs, "workflow_call"),
        new Set([...all].filter((j) => !["coverage", "fixup-queue", "test-ignored"].includes(j))),
    );
});

test("nightly-full drives the daily full-matrix run through ci.yml", () => {
    const on = topBlock(nightly, "on");
    assert.match(on, /cron:\s*"7 8 \* \* \*"/);
    assert.match(on, /^  workflow_dispatch:/m);
    assert.match(nightly, /uses:\s*\.\/\.github\/workflows\/ci\.yml/);
});

test("superseded PR runs cancel in both workflows", () => {
    for (const [name, yaml] of [["ci.yml", ci], ["codeql.yml", codeql]]) {
        assert.match(
            yaml,
            /cancel-in-progress:\s*\$\{\{\s*github\.event_name\s*==\s*'pull_request'\s*\}\}/,
            `${name} must cancel superseded pull_request runs`,
        );
    }
});

test("the Test matrix only emits the three canonical OS check names", () => {
    const matrixExprs = [...ci.matchAll(/fromJSON\(([^)]*)\)/g)].map((m) => m[1]);
    const testMatrix = matrixExprs.find((e) => e.includes("-latest"));
    assert.ok(testMatrix, "ci.yml Test matrix expression not found");
    for (const osLabel of ALL_OSES) {
        assert.ok(testMatrix.includes(`"${osLabel}"`), `${osLabel} missing`);
    }
});

// ---------------------------------------------------------------------------
// CI Gate: the single required check can never be left pending

test("CI Gate always runs and its needs list covers every gated job", () => {
    const gate = ciJobs.get("gate");
    assert.ok(gate, "gate job missing");
    assert.match(gate.if ?? "", /always\(\)/);
    // coverage is deliberately ungated (a Codecov outage must not become a
    // required check); fixup-queue depends on the gate, not vice versa.
    const ungated = new Set(["gate", "coverage", "fixup-queue"]);
    const expected = new Set([...ciJobs.keys()].filter((j) => !ungated.has(j)));
    assert.deepEqual(new Set(gate.needs), expected, "gate needs inventory drifted from jobs:");
    assert.ok(ciJobs.get("fixup-queue")?.needs.includes("gate"), "fixup-queue must need the gate");
});

// ---------------------------------------------------------------------------
// codeql.yml: PR analysis stays diff-scoped (rust only when rust changed)

test("CodeQL matrix comes from the classify languages output", () => {
    const analyze = codeqlJobs.get("analyze");
    assert.ok(analyze, "analyze job missing");
    assert.deepEqual(analyze.needs, ["classify"]);
    assert.match(analyze.if ?? "", /needs\.classify\.outputs\.code == 'true'/);
    assert.match(codeql, /languages:\s*\$\{\{\s*steps\.classify\.outputs\.languages\s*\}\}/);
    assert.match(
        codeql,
        /language:\s*\$\{\{\s*fromJSON\(needs\.classify\.outputs\.languages\)\s*\}\}/,
    );
    assert.match(codeql, /build-mode:\s*none/);
});

test("CodeQL rust analysis on PRs is bound to rust/Cargo paths or itself", () => {
    // Non-PR events scan every language.
    assert.match(
        codeql,
        /all='\["actions","javascript-typescript","python","ruby","rust"\]'/,
    );
    assert.match(codeql, /languages=\$all/);
    // On PRs the rust arm is gated by the .rs/Cargo classifier (or a change to
    // the workflow itself, which selects every language).
    const rustLine = codeql
        .split("\n")
        .find((l) => l.includes("langs+=(rust)"));
    assert.ok(rustLine, "rust language selection line missing");
    assert.match(rustLine, /\\\.rs\$\|\(\^\|\/\)Cargo\\\.\(toml\|lock\)\$/);
    assert.match(codeql, /has '\^\\\.github\/workflows\/codeql\\\.yml\$'/);
    // A PR touching no classified language skips analysis entirely.
    assert.match(codeql, /if \[ "\$\{#langs\[@\]\}" -eq 0 \]; then code=false/);
});

test("CodeQL classification only diffs on pull_request", () => {
    const classify = topBlock(codeql, "jobs").split("  analyze:")[0];
    assert.match(
        classify,
        /if:\s*github\.event_name == 'pull_request'/,
        "classify must only check out and diff on pull_request",
    );
});
