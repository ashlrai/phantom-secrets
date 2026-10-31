import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
    ALL_OSES,
    classifyFiles,
    cronInWindow,
    estimateWall,
    loadSchedule,
    parseCron,
    resolvePlan,
    rustCfgLegs,
    validateSchedule,
} from "./daily-matrix.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const tool = join(repoRoot, "scripts", "ci", "daily-matrix.mjs");
const schedule = loadSchedule();
const BUDGET = schedule.wallBudgetSeconds;

const MAC = "macos-latest";
const UBU = "ubuntu-latest";
const WIN = "windows-latest";

// readFile stub: map of path -> contents; missing key means unreadable.
const rf = (files = {}) => (p) => (p in files ? files[p] : null);
const PLAIN_RS = "fn helper() -> u32 { 1 }\n";

function os(files, contents = {}) {
    return classifyFiles(files, rf(contents)).os;
}

// ---------------------------------------------------------------------------
// Path classification

test("empty and docs-only diffs select no legs", () => {
    assert.deepEqual(os([]), []);
    assert.deepEqual(os(["README.md", "docs/guide.md", "changelog.d/x.md", "LICENSE", "NOTICE"]), []);
    assert.deepEqual(os(["apps/web/src/page.tsx", "scripts/seo/run.mjs", "video/demo.mp4"]), []);
});

test("a plain .rs change selects the canonical ubuntu leg only", () => {
    assert.deepEqual(os(["crates/phantom-core/src/lib.rs"], { "crates/phantom-core/src/lib.rs": PLAIN_RS }), [UBU]);
});

test("workspace-global changes select every leg", () => {
    for (const f of [
        "Cargo.toml", "Cargo.lock", "crates/phantom-core/Cargo.toml",
        "rust-toolchain.toml", "deny.toml", "Makefile", "build.rs",
        "crates/phantom-vault/build.rs", ".github/workflows/ci.yml",
        ".github/actions/setup/action.yml", "npm/install.js", "npm-mcp/bin/x",
        "mcp-registry/server.json", "scripts/release/check-version-parity.mjs",
        "scripts/install.sh", "scripts/install.ps1", "scripts/installers.test.js",
        "scripts/check-platform-installers.mjs", "apps/web/public/install.sh",
        "apps/web/public/install.ps1", "scripts/ci/daily-matrix.mjs",
        "scripts/ci/offpeak-schedule.json", "scripts/ci/daily-matrix.test.mjs",
    ]) {
        assert.deepEqual(os([f]), ALL_OSES, f);
    }
});

test("platform-named non-Rust paths select their leg", () => {
    assert.deepEqual(os(["tools/deploy.ps1"]), [WIN]);
    assert.deepEqual(os(["integrations/macos-entitlements.plist"]), [MAC]);
    assert.deepEqual(os(["scripts/unix/perms.sh"]), [MAC, UBU]);
    assert.deepEqual(os(["examples/platform-check/x.txt"]), ALL_OSES);
});

test("unattributable and linux-named files default to the ubuntu leg", () => {
    assert.deepEqual(os(["integrations/foo.json"]), [UBU]);
    assert.deepEqual(os(["scripts/bench/linux-run.sh"]), [UBU]);
});

test(".rs cfg selectors add their named legs", () => {
    const cases = [
        ["#[cfg(windows)]\nfn w() {}", [WIN]],
        ["#[cfg(unix)]\nfn u() {}", [MAC, UBU]],
        ["#[cfg(target_os = \"macos\")]\nfn m() {}", [MAC]],
        ["#[cfg(target_os = \"linux\")]\nfn l() {}", [UBU]],
        ["#[cfg(target_family = \"unix\")]\nfn u() {}", [MAC, UBU]],
        ["#[cfg(target_family = \"windows\")]\nfn w() {}", [WIN]],
        ["#[cfg(not(windows))]\nfn n() {}", [MAC, UBU]],
        ["#[cfg(not(unix))]\nfn n() {}", [WIN]],
        ["#[cfg(not(target_os = \"linux\"))]\nfn n() {}", [MAC, WIN]],
        ["#[cfg(not(target_os = \"wasi\"))]\nfn n() {}", ALL_OSES],
        ["#[cfg(not(test))]\nfn n() {}", []],
        ["#[cfg(not(feature = \"pq-hybrid\"))]\nfn n() {}", []],
        ["#[cfg(any(unix, windows))]\nfn a() {}", ALL_OSES],
        ["#[cfg(all(unix, target_os = \"macos\"))]\nfn a() {}", [MAC, UBU]],
        ["#[cfg(not(any(target_os = \"macos\", target_os = \"windows\")))]\nfn a() {}", [UBU]],
        ["#[cfg(not(all(target_os = \"linux\", target_env = \"gnu\")))]\nfn a() {}", ALL_OSES],
        ["#[cfg(test)]\nfn t() {}", []],
        ["#[cfg(feature = \"pq-hybrid\")]\nfn f() {}", []],
        ["#[cfg(miri)]\nfn m() {}", []],
        ["#[cfg(target_arch = \"x86_64\")]\nfn a() {}", ALL_OSES],
        ["#[cfg(target_env = \"gnu\")]\nfn a() {}", ALL_OSES],
        ["#[cfg(phantom_unlisted_atom)]\nfn u() {}", ALL_OSES],
        ["#[cfg_attr(unix, derive(Debug))]\nstruct S;", [MAC, UBU]],
        ["#[cfg_attr(test, derive(Debug))]\nstruct S;", []],
        ["let ok = cfg!(windows);", [WIN]],
        ["let ok = cfg!(not(unix));", [WIN]],
    ];
    for (const [src, want] of cases) {
        const legs = rustCfgLegs(src);
        const got = ALL_OSES.filter((o) => legs.has(o));
        assert.deepEqual(got, want, src);
    }
});

test(".rs with platform selectors also selects the named legs", () => {
    const src = "#[cfg(unix)]\nfn u() {}\n#[cfg(not(unix))]\nfn w() {}\n";
    assert.deepEqual(os(["crates/x/src/lib.rs"], { "crates/x/src/lib.rs": src }), ALL_OSES);
    assert.deepEqual(
        os(["crates/x/src/windows_helpers.rs"], { "crates/x/src/windows_helpers.rs": PLAIN_RS }),
        [UBU, WIN],
    );
});

test("an unreadable or deleted .rs selects every leg", () => {
    assert.deepEqual(os(["crates/x/src/gone.rs"]), ALL_OSES);
});

test("mixed diffs union legs in canonical order", () => {
    const files = ["tools/deploy.ps1", "crates/x/src/lib.rs", "README.md"];
    const got = os(files, { "crates/x/src/lib.rs": PLAIN_RS });
    assert.deepEqual(got, [UBU, WIN]);
});

// ---------------------------------------------------------------------------
// Schedule data and cron

test("offpeak-schedule.json validates", () => {
    assert.deepEqual(validateSchedule(schedule), []);
});

test("configured cron lands inside the off-peak window", () => {
    assert.ok(cronInWindow(schedule.cron, schedule.windowUtc));
    // The existing 08:07 UTC run is a peer, not inside the window.
    assert.equal(cronInWindow("7 8 * * *", schedule.windowUtc), false);
});

test("parseCron accepts standard field forms and rejects junk", () => {
    assert.deepEqual([...parseCron("43 3 * * *").minute], [43]);
    assert.deepEqual([...parseCron("*/15 * * * *").minute], [0, 15, 30, 45]);
    assert.deepEqual([...parseCron("0 2-5 * * *").hour], [2, 3, 4, 5]);
    assert.deepEqual([...parseCron("1,7,9 * * * *").minute], [1, 7, 9]);
    assert.throws(() => parseCron("43 3 * *"));
    assert.throws(() => parseCron("99 3 * * *"));
    assert.throws(() => parseCron("x y z w v"));
    assert.throws(() => parseCron("*/0 * * * *"));
});

test("cronInWindow requires every fire time inside the window", () => {
    const w = schedule.windowUtc;
    assert.equal(cronInWindow("0 2,3,4 * * *", w), true);
    assert.equal(cronInWindow("30 1-6 * * *", w), false);
    assert.equal(cronInWindow("0 5 * * 1", w), true);
    assert.equal(cronInWindow("7 8 * * *", w), false);
});

test("validateSchedule rejects bad shapes", () => {
    const bad = (patch) => validateSchedule({ ...structuredClone(schedule), ...patch });
    assert.ok(bad({ cron: "7 8 * * *" }).some((e) => e.includes("outside")));
    assert.ok(bad({ cron: "not a cron" }).some((e) => e.includes("cron")));
    assert.ok(bad({ windowUtc: { startMinutes: 500, endMinutes: 100 } }).length);
    assert.ok(bad({ minPeerGapMinutes: -1 }).length);
    const colliding = structuredClone(schedule);
    colliding.peers = [{ name: "x", cron: "0 4 * * *" }];
    colliding.cron = "20 4 * * *"; // 20 min from peer, under the 30m gap
    assert.ok(validateSchedule(colliding).some((e) => e.includes("peer")));
    const missing = structuredClone(schedule);
    delete missing.estimatesSeconds.perLeg[WIN];
    assert.ok(validateSchedule(missing).some((e) => e.includes("perLeg")));
});

// ---------------------------------------------------------------------------
// Wall estimate against the 900s acceptance budget

test("off-peak wall estimate meets the budget for every selection", () => {
    for (const legs of [[], [UBU], [UBU, WIN], ALL_OSES]) {
        const est = estimateWall(legs, schedule);
        assert.ok(est <= BUDGET, `est ${est} for [${legs}] exceeds ${BUDGET}`);
    }
    assert.equal(estimateWall([], schedule), schedule.estimatesSeconds.fixedOverhead);
    assert.equal(
        estimateWall(ALL_OSES, schedule),
        schedule.estimatesSeconds.fixedOverhead + Math.max(...Object.values(schedule.estimatesSeconds.perLeg)),
    );
});

// ---------------------------------------------------------------------------
// resolvePlan

test("resolvePlan fails closed to the full matrix", () => {
    const env = { readFile: rf({}), diffFiles: () => null };
    assert.deepEqual(resolvePlan({ full: true }, env).os, ALL_OSES);
    assert.deepEqual(resolvePlan({ files: null, base: null, since: null }, env).os, ALL_OSES);
    assert.deepEqual(resolvePlan({ files: null, base: "abc", since: null }, env).os, ALL_OSES);
    const plan = resolvePlan(
        { files: null, base: null, since: 24 },
        { readFile: rf({}), diffFiles: () => ["crates/x/a.rs"] },
    );
    assert.deepEqual(plan.os, ALL_OSES); // a.rs unreadable -> fail closed
});

// ---------------------------------------------------------------------------
// Contract: required check names are unchanged (reads ci.yml, writes nothing)

test("every emitted OS label is a check name ci.yml already produces", () => {
    const ci = readFileSync(join(repoRoot, ".github", "workflows", "ci.yml"), "utf8");
    assert.match(ci, /name: Test \(\$\{\{ matrix\.os \}\}\)/);
    assert.match(ci, /name: CI Gate/); // the single required check
    const matrixExprs = [...ci.matchAll(/fromJSON\(([^)]*)\)/g)].map((m) => m[1]);
    const testMatrix = matrixExprs.find((e) => e.includes("-latest"));
    assert.ok(testMatrix, "ci.yml Test matrix expression not found");
    for (const osLabel of ALL_OSES) {
        assert.ok(testMatrix.includes(`"${osLabel}"`), `${osLabel} missing from ci.yml matrix`);
    }
});

// ---------------------------------------------------------------------------
// CLI end-to-end

function run(args, { cwd = repoRoot, input, env } = {}) {
    return spawnSync(process.execPath, [tool, ...args], {
        cwd, input, encoding: "utf8", env: { ...process.env, ...env },
    });
}

test("CLI matrix prints a JSON array for fromJSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "dm-"));
    writeFileSync(join(dir, "list.txt"), "crates/x/a.rs\n");
    const r = run(["--files", join(dir, "list.txt")], { cwd: dir });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout.trim()), ALL_OSES); // a.rs unreadable -> all
});

test("CLI --files - reads stdin and --full overrides", () => {
    const dir = mkdtempSync(join(tmpdir(), "dm-"));
    const r = run(["--files", "-"], { cwd: dir, input: "README.md\n" });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout.trim()), []);
    const f = run(["--full"], { cwd: dir });
    assert.equal(f.status, 0, f.stderr);
    assert.deepEqual(JSON.parse(f.stdout.trim()), ALL_OSES);
});

test("CLI --github-output writes os_matrix to GITHUB_OUTPUT", () => {
    const dir = mkdtempSync(join(tmpdir(), "dm-"));
    const out = join(dir, "out.txt");
    writeFileSync(join(dir, "list.txt"), "docs/x.md\n");
    const r = run(["--files", "list.txt", "--github-output"], { cwd: dir, env: { GITHUB_OUTPUT: out } });
    assert.equal(r.status, 0, r.stderr);
    assert.match(readFileSync(out, "utf8"), /^os_matrix=\[\]$/m);
});

test("CLI cron subcommand", () => {
    const r = run(["cron"]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), schedule.cron);
    assert.equal(run(["cron", "--check", "43 3 * * *"]).status, 0);
    assert.equal(run(["cron", "--check", "7 8 * * *"]).status, 1);
    const y = run(["cron", "--yaml"]);
    assert.equal(y.status, 0, y.stderr);
    assert.match(y.stdout, /schedule:/);
    assert.match(y.stdout, new RegExp(schedule.cron.replace(/\*/g, "\\*")));
    assert.match(y.stdout, /7 8 \* \* \*/);
});

test("CLI estimate and check-schedule", () => {
    const dir = mkdtempSync(join(tmpdir(), "dm-"));
    const e = run(["estimate", "--full"], { cwd: dir });
    assert.equal(e.status, 0, e.stderr);
    const n = Number(e.stdout.trim());
    assert.ok(n > 0 && n <= BUDGET);
    const c = run(["check-schedule"]);
    assert.equal(c.status, 0, c.stderr);
    assert.match(c.stdout, /OK/);
});

test("CLI --base/--head resolves a real git diff", () => {
    const dir = mkdtempSync(join(tmpdir(), "dm-git-"));
    const git = (...a) => execFileSync("git", a, { cwd: dir, encoding: "utf8" });
    git("init", "-q");
    git("config", "user.email", "t@t");
    git("config", "user.name", "t");
    writeFileSync(join(dir, "a.rs"), "fn a() {}\n");
    git("add", "a.rs");
    git("commit", "-qm", "one");
    const base = git("rev-parse", "HEAD").trim();
    writeFileSync(join(dir, "a.rs"), "#[cfg(windows)]\nfn a() {}\n");
    git("commit", "-qam", "two");
    const r = run(["--base", base], { cwd: dir });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout.trim()), [UBU, WIN]);
});

test("CLI exits nonzero on a bad subcommand", () => {
    const r = run(["frobnicate"]);
    assert.equal(r.status, 2);
});
