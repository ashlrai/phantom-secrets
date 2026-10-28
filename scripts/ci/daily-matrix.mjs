#!/usr/bin/env node
// Compute the affected-only OS matrix for the `Test (${{ matrix.os }})` job and
// the additive off-peak cron for the daily full-suite run. See
// scripts/ci/daily-matrix.md for the design and the workflow patch this powers.
//
// Subcommands:
//   matrix [opts]   (default) print the JSON OS array for fromJSON(...)
//   estimate [opts] print the projected off-peak wall time in seconds
//   cron [--check EXPR | --yaml]  print / validate the configured off-peak cron
//   check-schedule  validate offpeak-schedule.json (schema, window, stagger)
//
// File-selection opts (first wins; none selects the full matrix):
//   --files PATH|-      newline-separated changed paths ('-' reads stdin)
//   --base SHA [--head SHA]   git diff --name-only BASE...HEAD
//   --since HOURS       diff HEAD against `git rev-list -n1 --before="N hours ago"`
//   --full              force all three OS legs (escape hatch, e.g. ci:full-os)
// Output opts: --github-output appends os_matrix=<json> to $GITHUB_OUTPUT;
//   --explain prints per-leg reasons and the wall estimate to stderr.
//
// The direction of every rule is fail-closed toward MORE coverage: an
// unreadable or unclassifiable input selects more OS legs, never fewer.

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ALL_OSES = ["macos-latest", "ubuntu-latest", "windows-latest"];
export const UBUNTU = "ubuntu-latest";

const SCHEDULE_PATH = join(
    dirname(fileURLToPath(import.meta.url)),
    "offpeak-schedule.json",
);

// ---------------------------------------------------------------------------
// Path classification. Order matters: global triggers first, then
// docs/non-matrix surfaces, then per-file routing.

// Files that can change build or test behavior on every OS leg.
const GLOBAL_RES = [
    /^\.github\/(workflows|actions)\//, // CI itself affects every leg
    /(^|\/)Cargo\.(toml|lock)$/, // workspace/crate manifests and lockfiles
    /(^|\/)rust-toolchain(\.toml)?$/,
    /^\.cargo\//,
    /^\.config\/nextest/,
    /^deny\.toml$/,
    /^(clippy|rustfmt)\.toml$/,
    /(^|\/)build\.rs$/, // build scripts can emit platform-specific code
    /^Makefile$/,
    /^scripts\/release\//,
    /^scripts\/install\.(sh|ps1)$/,
    /^scripts\/check-platform-installers\.mjs$/,
    /^scripts\/installers\.test\.js$/,
    /^apps\/web\/public\/install\./, // verified on every leg
    /^npm(-mcp)?\//, // wrappers are per-OS; platform-matrix tests run on each leg
    /^mcp-registry\//,
    /^scripts\/ci\/daily-matrix\./, // this tool governs the legs themselves
    /^scripts\/ci\/offpeak-schedule\.json$/,
];

// Changes that no `Test (${{ matrix.os }})` leg can observe: documentation and
// surfaces exercised only by non-matrix jobs (web, supabase, seo). No crate
// ever include_str!()s a Markdown file, so *.md is unconditionally docs.
const INERT_RES = [
    /\.(md|mdx|rst)$/i,
    /^LICENSE(\.[^/]*)?$/,
    /^NOTICE$/,
    /^docs\//,
    /^changelog\.d\//,
    /^\.github\/(ISSUE_TEMPLATE|PULL_REQUEST_TEMPLATE)/,
    /^CODEOWNERS$/,
    /^CITATION\.cff$/,
    /^apps\/web\//,
    /^scripts\/(supabase|seo)\//,
    /^video\//,
];

// Path keywords that mark a non-Rust file as platform-relevant. Every matching
// group contributes its legs.
const PATH_KEYWORDS = [
    [/windows|win32|win64|wincred|msvc|powershell|\.ps1$|\.psm1$|\.bat$|\.cmd$/i, ["windows-latest"]],
    [/macos|darwin|\.plist$|\.entitlements$|\.dmg$/i, ["macos-latest"]],
    [/(^|\/)(linux|secretservice|secret[-_]service|systemd)/i, [UBUNTU]],
    [/(^|\/)unix|(^|\/)posix/i, ["macos-latest", UBUNTU]],
    [/(^|\/)platform/i, "all"],
];

// cfg atoms we recognize as OS selectors.
const OS_TOKENS = {
    windows: ["windows-latest"],
    unix: ["macos-latest", UBUNTU],
    macos: ["macos-latest"],
    linux: [UBUNTU],
};
const FAMILY_TOKENS = { windows: ["windows-latest"], unix: ["macos-latest", UBUNTU] };
// target_os values we know exist but do not run a leg for; an unrecognized
// name (a typo or a brand-new target) fails closed to the full matrix.
const UNTESTED_OS = new Set([
    "aix", "android", "cuda", "cygwin", "dragonfly", "emscripten", "espidf",
    "freebsd", "fuchsia", "haiku", "hermit", "horizon", "hurd", "illumos",
    "ios", "l4re", "linux_?", "netbsd", "none", "nto", "openbsd", "psp",
    "redox", "rtems", "serenity", "solaris", "solid_asp3", "teeos", "tvos",
    "uefi", "uwp", "vexos", "vita", "vxworks", "wasi", "watchos", "visionos",
    "xous", "zkvm",
]);
// cfg atoms that are not platform selectors; anything else inside a cfg
// expression is unknown and fails closed to the full matrix.
const NON_OS_CFG = new Set([
    "all", "any", "not", "feature", "test", "miri", "doc", "docsrs", "doctest",
    "debug_assertions", "coverage", "coverage_nightly", "fuzzing", "loom",
    "tokio_unstable", "tracing_unstable", "backtrace", "sanitize", "sanitizers",
    "kani", "valgrind", "bench", "clippy", "rustfmt", "target_thread_local",
    "ub_checks", "phantom_test", "false", "true", "proc_macro", "cfg", "cfg_attr",
    "target_os", "target_family",
]);
// Platform-tuple selectors we cannot map to a subset of legs.
const WIDE_CFG = new Set([
    "target_arch", "target_env", "target_abi", "target_vendor", "target_endian",
    "target_pointer_width", "target_feature", "target_has_atomic",
    "target_has_atomic_equal_alignment", "target_has_atomic_load_store",
    "panic", "relocation_model", "abi",
]);

function isGlobal(path) {
    return GLOBAL_RES.some((re) => re.test(path));
}

function isInert(path) {
    return INERT_RES.some((re) => re.test(path));
}

function isRust(path) {
    return path.endsWith(".rs");
}

// Split a comma-separated cfg argument list at paren depth 0.
function splitTopLevel(text) {
    const parts = [];
    let depth = 0;
    let start = 0;
    for (let i = 0; i < text.length; i += 1) {
        if (text[i] === "(") depth += 1;
        else if (text[i] === ")") depth -= 1;
        else if (text[i] === "," && depth === 0) {
            parts.push(text.slice(start, i));
            start = i + 1;
        }
    }
    parts.push(text.slice(start));
    return parts.map((p) => p.trim()).filter(Boolean);
}

// Return the balanced parenthesized body starting at the open paren index.
function parenBody(text, openIdx) {
    let depth = 0;
    for (let i = openIdx; i < text.length; i += 1) {
        if (text[i] === "(") depth += 1;
        else if (text[i] === ")") {
            depth -= 1;
            if (depth === 0) return { body: text.slice(openIdx + 1, i), end: i };
        }
    }
    return { body: text.slice(openIdx + 1), end: text.length };
}

// Classify one cfg selector.
//   Set<os>  — an OS selector (possibly empty for a known untested target)
//   "none"   — a non-OS cfg atom (test, feature, ...) selects no legs
//   "wide"   — a platform tuple we cannot subset (target_arch, ...) -> all legs
//   "unknown" — unrecognized atom -> fail closed to all legs
function selectorLegs(raw) {
    const p = raw.trim().toLowerCase();
    const kv = p.match(/^([a-z_][a-z_0-9]*)\s*=\s*"?([^"\s]+)"?$/);
    if (kv) {
        const [, key, name] = kv;
        if (key === "target_os") {
            if (OS_TOKENS[name]) return new Set(OS_TOKENS[name]);
            if (UNTESTED_OS.has(name)) return new Set();
            return "unknown";
        }
        if (key === "target_family") {
            if (FAMILY_TOKENS[name]) return new Set(FAMILY_TOKENS[name]);
            return "wide";
        }
        // feature="x" and other non-OS key/value atoms select no legs;
        // target_* and unrecognized keys fail closed wide.
        return NON_OS_CFG.has(key) ? "none" : "wide";
    }
    if (p.startsWith("target_")) return "wide";
    if (OS_TOKENS[p]) return new Set(OS_TOKENS[p]);
    if (NON_OS_CFG.has(p)) return "none";
    if (WIDE_CFG.has(p)) return "wide";
    return "unknown";
}

// Union selectorLegs over a comma-separated selector list.
// osSpecific records whether any selector was an OS selector at all: a
// not() over only non-OS atoms (test, feature) narrows nothing.
function unionSelectors(text) {
    const legs = new Set();
    let osSpecific = false;
    for (const part of splitTopLevel(text)) {
        const r = selectorLegs(part);
        if (r instanceof Set) {
            osSpecific = true;
            r.forEach((os) => legs.add(os));
        } else if (r === "none") continue;
        else return { fail: r };
    }
    return { legs, osSpecific };
}

// Map one cfg expression body to legs. markAll() escalates to the full matrix.
function mapCfgBody(body, legs, markAll) {
    let rest = body;

    // not(X) selects the complement of X within the tested OS set. Each clause
    // is excised after evaluation so its inner tokens cannot double-count in
    // the positive scan below.
    const notRe = /\bnot\s*\(/g;
    const spans = [];
    let nm;
    while ((nm = notRe.exec(rest)) !== null) {
        const { body: inner0, end } = parenBody(rest, nm.index + nm[0].length - 1);
        spans.push([nm.index, end + 1]);
        const inner = inner0.trim();
        const anyM = inner.match(/^any\s*\(([\s\S]*)\)$/);
        if (inner.match(/^(all|not)\s*\(/)) {
            markAll(); // complement of an intersection/nested not: not OS-expressible
        } else {
            const sel = unionSelectors(anyM ? anyM[1] : inner);
            if (sel.fail) markAll();
            // A not() over only non-OS atoms (test, feature) narrows nothing;
            // over an OS selector it selects the complement within our legs.
            else if (sel.osSpecific) {
                for (const os of ALL_OSES.filter((o) => !sel.legs.has(o))) legs.add(os);
            }
        }
    }
    for (let i = spans.length - 1; i >= 0; i -= 1) {
        rest = rest.slice(0, spans[i][0]) + " ".repeat(spans[i][1] - spans[i][0]) + rest.slice(spans[i][1]);
    }

    // name = "value" selectors: only target_os/target_family map to a subset;
    // non-OS keys (feature, ...) are inert here, and everything else — every
    // other target_* tuple, unknown keys — fails closed to the full matrix.
    for (const t of rest.matchAll(/\b([a-z_][a-z_0-9]*)\s*=\s*"([^"]*)"/gi)) {
        const key = t[1].toLowerCase();
        const val = t[2].toLowerCase();
        if (key === "target_os") {
            if (OS_TOKENS[val]) OS_TOKENS[val].forEach((os) => legs.add(os));
            else if (!UNTESTED_OS.has(val)) markAll();
        } else if (key === "target_family") {
            const l = FAMILY_TOKENS[val];
            if (l) l.forEach((os) => legs.add(os));
            else markAll();
        } else if (!NON_OS_CFG.has(key)) markAll();
    }
    rest = rest.replace(/\b[a-z_][a-z_0-9]*\s*=\s*"[^"]*"/gi, " ").replace(/"/g, " ");
    for (const t of rest.matchAll(/\b([a-z_][a-z_0-9]*)\b/gi)) {
        const tok = t[1].toLowerCase();
        if (OS_TOKENS[tok]) OS_TOKENS[tok].forEach((os) => legs.add(os));
        else if (WIDE_CFG.has(tok)) markAll();
        else if (NON_OS_CFG.has(tok) || tok.startsWith("cfg")) continue;
        else markAll(); // unknown cfg atom: fail closed to the full matrix
    }
}

// Extract legs named by cfg/cfg!/cfg_attr expressions in Rust source.
// cfg_attr's second+ arguments are attribute payloads, not selectors.
export function rustCfgLegs(source) {
    const legs = new Set();
    let all = false;
    const markAll = () => { all = true; };
    const exprRe = /\b(cfg!?|cfg_attr)\s*\(/g;
    let m;
    while ((m = exprRe.exec(source)) !== null) {
        const openIdx = m.index + m[0].length - 1;
        const { body, end } = parenBody(source, openIdx);
        exprRe.lastIndex = end + 1;
        // cfg_attr: only its first comma-separated argument is a cfg selector.
        const cfgPart = m[1] === "cfg_attr" ? splitTopLevel(body)[0] ?? "" : body;
        mapCfgBody(cfgPart, legs, markAll);
    }
    return all ? new Set(ALL_OSES) : legs;
}

// Legs implied by a non-Rust path's name, "all", or an empty set.
function pathKeywordLegs(path) {
    const legs = new Set();
    let all = false;
    for (const [re, l] of PATH_KEYWORDS) {
        if (!re.test(path)) continue;
        if (l === "all") all = true;
        else l.forEach((os) => legs.add(os));
    }
    return all ? "all" : legs;
}

function fullPlan(why) {
    return {
        os: [...ALL_OSES],
        reasons: Object.fromEntries(ALL_OSES.map((o) => [o, [why]])),
    };
}

/**
 * Classify changed paths into the OS legs they can affect.
 * `readFile(path)` returns file contents or null when unreadable/deleted.
 * Returns { os: [...ordered subset of ALL_OSES...], reasons: {os: [why]} }.
 */
export function classifyFiles(files, readFile) {
    const legs = new Set();
    const reasons = new Map();
    const add = (os, why) => {
        legs.add(os);
        if (!reasons.has(os)) reasons.set(os, new Set());
        reasons.get(os).add(why);
    };
    const addAll = (why) => ALL_OSES.forEach((os) => add(os, why));

    for (const raw of files) {
        const f = raw.trim();
        if (!f) continue;
        // Global triggers win over inert surfaces: the installer scripts under
        // apps/web/public/ are verified on every leg.
        if (isGlobal(f)) { addAll(`global: ${f}`); continue; }
        if (isInert(f)) continue;
        if (isRust(f)) {
            const body = readFile(f);
            if (body === null) { addAll(`unreadable: ${f}`); continue; }
            add(UBUNTU, `rust: ${f}`); // every .rs change tests on the canonical leg
            for (const os of rustCfgLegs(body)) add(os, `cfg: ${f}`);
            const named = pathKeywordLegs(f);
            if (named === "all") addAll(`platform: ${f}`);
            else named.forEach((os) => add(os, `path: ${f}`));
            continue;
        }
        const named = pathKeywordLegs(f);
        if (named === "all") { addAll(`platform: ${f}`); continue; }
        if (named.size) named.forEach((os) => add(os, `path: ${f}`));
        else add(UBUNTU, `default: ${f}`); // not platform-attributable; canonical leg covers it
    }
    return {
        os: ALL_OSES.filter((o) => legs.has(o)),
        reasons: Object.fromEntries(
            [...reasons.entries()].map(([k, v]) => [k, [...v].sort()]),
        ),
    };
}

// ---------------------------------------------------------------------------
// Schedule data and cron evaluation.

export function loadSchedule(path = SCHEDULE_PATH) {
    const raw = JSON.parse(readFileSync(path, "utf8"));
    const errors = validateSchedule(raw);
    if (errors.length) {
        throw new Error(`${path}: invalid schedule: ${errors.join("; ")}`);
    }
    return raw;
}

export function validateSchedule(s) {
    const errors = [];
    const w = s?.windowUtc;
    if (!w || !Number.isInteger(w.startMinutes) || !Number.isInteger(w.endMinutes)
        || w.startMinutes < 0 || w.endMinutes > 1440 || w.startMinutes >= w.endMinutes) {
        errors.push("windowUtc must be integer minutes with 0 <= start < end <= 1440");
    } else {
        try {
            if (!cronInWindow(s?.cron, w)) errors.push(`cron ${s?.cron} fires outside windowUtc`);
        } catch (e) { errors.push(`cron: ${e.message}`); }
    }
    const gap = s?.minPeerGapMinutes;
    if (!Number.isInteger(gap) || gap < 0) errors.push("minPeerGapMinutes must be a non-negative integer");
    else {
        let slot = null;
        try { slot = fireMinutes(s?.cron); } catch { /* reported above */ }
        for (const [i, p] of (s?.peers ?? []).entries()) {
            let pm = null;
            try { pm = fireMinutes(p?.cron); } catch (e) { errors.push(`peers[${i}].cron: ${e.message}`); }
            if (slot !== null && pm !== null && Math.abs(slot - pm) < gap) {
                errors.push(`cron is ${Math.abs(slot - pm)}m from peer ${p.name}; need >= ${gap}m`);
            }
        }
    }
    const legs = s?.estimatesSeconds?.perLeg ?? {};
    for (const os of ALL_OSES) {
        if (!Number.isFinite(legs[os]) || legs[os] <= 0) errors.push(`estimatesSeconds.perLeg.${os} missing`);
    }
    if (!Number.isFinite(s?.estimatesSeconds?.fixedOverhead) || s.estimatesSeconds.fixedOverhead < 0) {
        errors.push("estimatesSeconds.fixedOverhead missing");
    }
    if (!Number.isInteger(s?.wallBudgetSeconds) || s.wallBudgetSeconds <= 0) {
        errors.push("wallBudgetSeconds must be a positive integer");
    }
    return errors;
}

// Minimal 5-field cron parser supporting '*', lists, ranges and steps.
export function parseCron(expr) {
    const fields = String(expr ?? "").trim().split(/\s+/);
    if (fields.length !== 5) throw new Error(`expected 5 fields, got ${fields.length}`);
    const field = (f, lo, hi) => {
        const out = new Set();
        for (const part of f.split(",")) {
            const m = part.match(/^(\*|\d+|\d+-\d+)(?:\/(\d+))?$/);
            if (!m) throw new Error(`bad field ${part} in ${expr}`);
            let a = lo;
            let b = hi;
            if (m[1] !== "*") {
                if (m[1].includes("-")) [a, b] = m[1].split("-").map(Number);
                else a = b = Number(m[1]);
            }
            const step = m[2] ? Number(m[2]) : 1;
            if (a < lo || b > hi || a > b || step < 1) throw new Error(`field ${part} out of range`);
            for (let v = a; v <= b; v += step) out.add(v);
        }
        return out;
    };
    const minute = field(fields[0], 0, 59);
    const hour = field(fields[1], 0, 23);
    field(fields[2], 1, 31);
    field(fields[3], 1, 12);
    field(fields[4], 0, 7);
    return { minute, hour };
}

// The single minute-of-day the cron fires at, or null for multi-fire schedules.
function fireMinutes(expr) {
    const { minute, hour } = parseCron(expr);
    const times = [...hour].flatMap((h) => [...minute].map((mi) => h * 60 + mi));
    return times.length === 1 ? times[0] : null;
}

export function cronInWindow(expr, windowUtc) {
    const { minute, hour } = parseCron(expr);
    for (const h of hour) {
        for (const mi of minute) {
            const t = h * 60 + mi;
            if (t < windowUtc.startMinutes || t >= windowUtc.endMinutes) return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Wall-time estimate: off-peak the legs run in parallel behind a ~zero queue,
// so wall ~= fixed overhead + the slowest selected leg.
export function estimateWall(osList, schedule = loadSchedule()) {
    const est = schedule.estimatesSeconds;
    const slowest = osList.reduce((acc, os) => Math.max(acc, est.perLeg[os] ?? 0), 0);
    return est.fixedOverhead + (osList.length ? slowest : 0);
}

// ---------------------------------------------------------------------------
// Diff resolution and CLI.

function gitDiffNames(base, head) {
    const out = execFileSync("git", ["diff", "--name-only", `${base}...${head}`], {
        encoding: "utf8",
    });
    return out.split("\n").filter(Boolean);
}

function baseSince(hours) {
    const out = execFileSync(
        "git",
        ["rev-list", "-n", "1", `--before=${hours} hours ago`, "HEAD"],
        { encoding: "utf8" },
    ).trim();
    return out || null;
}

function explain(plan, schedule, baseLabel) {
    const lines = [`os_matrix -> [${plan.os.join(", ") || "(none)"}]${baseLabel}`];
    for (const [os, why] of Object.entries(plan.reasons)) {
        lines.push(`  ${os}: ${why.join("; ")}`);
    }
    lines.push(`estimated_wall_seconds=${estimateWall(plan.os, schedule)} budget=${schedule.wallBudgetSeconds}`);
    return lines.join("\n");
}

function die(msg) {
    process.stderr.write(`daily-matrix: ${msg}\n`);
    process.exit(2);
}

function parseArgs(argv) {
    const opts = {
        files: null, base: null, head: "HEAD", since: null, full: false,
        explain: false, githubOutput: false, check: null, yaml: false,
    };
    const rest = [...argv];
    let sub = "matrix";
    if (rest[0] && !rest[0].startsWith("-")) sub = rest.shift();
    while (rest.length) {
        const a = rest.shift();
        switch (a) {
            case "--files": opts.files = rest.shift() ?? die("--files needs a value"); break;
            case "--base": opts.base = rest.shift() ?? die("--base needs a value"); break;
            case "--head": opts.head = rest.shift() ?? die("--head needs a value"); break;
            case "--since": opts.since = Number(rest.shift()); break;
            case "--full": opts.full = true; break;
            case "--explain": opts.explain = true; break;
            case "--github-output": opts.githubOutput = true; break;
            case "--check": opts.check = rest.shift() ?? die("--check needs a value"); break;
            case "--yaml": opts.yaml = true; break;
            case "--help": case "-h": sub = "help"; break;
            default: die(`unknown argument ${a}`);
        }
    }
    return { opts, sub };
}

export function resolvePlan(opts, { readFile, diffFiles }) {
    if (opts.full) return fullPlan("--full");
    let files;
    if (opts.files !== null) {
        try {
            files = (opts.files === "-"
                ? readFileSync(0, "utf8")
                : readFileSync(opts.files, "utf8")).split("\n");
        } catch (e) {
            die(`cannot read --files ${opts.files}: ${e.code ?? e.message}`);
        }
    } else if (opts.base) {
        files = diffFiles(opts.base, opts.head);
    } else if (opts.since !== null) {
        files = diffFiles(null, opts.head, opts.since);
    } else {
        return fullPlan("no diff context");
    }
    if (!files) return fullPlan("diff resolution failed"); // fail closed
    return classifyFiles(files, readFile);
}

function usage() {
    process.stdout.write(
        `daily-matrix.mjs — affected-only OS matrix and off-peak cron for the daily full-suite run

  matrix   [file opts] [--github-output] [--explain]  print JSON OS array (default)
  estimate [file opts]                                 print projected off-peak wall seconds
  cron     [--check "M H * * *" | --yaml]              print/validate the off-peak cron
  check-schedule                                       validate offpeak-schedule.json

File opts (first wins): --files PATH|- | --base SHA [--head SHA] | --since HOURS | --full
`,
    );
}

function main() {
    const { opts, sub } = parseArgs(process.argv.slice(2));
    const schedule = loadSchedule();

    switch (sub) {
        case "help": usage(); return;
        case "check-schedule": {
            const w = schedule.windowUtc;
            process.stdout.write(`offpeak-schedule.json OK: cron=${schedule.cron} window=${w.startMinutes}-${w.endMinutes} peers=${schedule.peers.length} budget=${schedule.wallBudgetSeconds}s\n`);
            return;
        }
        case "cron": {
            if (opts.yaml) {
                const peers = schedule.peers.map((p) => `    - cron: "${p.cron}"   # kept: ${p.name}`);
                process.stdout.write(
                    `schedule:\n${peers.join("\n")}\n    - cron: "${schedule.cron}"  # added: off-peak affected-only run\n`,
                );
                return;
            }
            if (opts.check !== null) {
                let ok = false;
                try { ok = cronInWindow(opts.check, schedule.windowUtc); } catch { ok = false; }
                if (!ok) { process.stderr.write(`${opts.check}: outside off-peak window\n`); process.exit(1); }
                process.stdout.write(`${opts.check}: inside off-peak window\n`);
                return;
            }
            process.stdout.write(`${schedule.cron}\n`);
            return;
        }
        case "matrix":
        case "estimate": {
            const root = process.cwd();
            const readFile = (f) => {
                try { return readFileSync(join(root, f), "utf8"); } catch { return null; }
            };
            const diffFiles = (base, head, since) => {
                try {
                    const b = base ?? baseSince(since);
                    if (!b) return null;
                    return gitDiffNames(b, head);
                } catch { return null; }
            };
            const plan = resolvePlan(opts, { readFile, diffFiles });
            if (sub === "estimate") {
                process.stdout.write(`${estimateWall(plan.os, schedule)}\n`);
                return;
            }
            const json = JSON.stringify(plan.os);
            if (opts.githubOutput) {
                const line = `os_matrix=${json}`;
                if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${line}\n`);
                else process.stdout.write(`${line}\n`);
            } else {
                process.stdout.write(`${json}\n`);
            }
            if (opts.explain) {
                const label = opts.since !== null ? ` (diff vs HEAD ~${opts.since}h ago)` : "";
                process.stderr.write(`${explain(plan, schedule, label)}\n`);
            }
            return;
        }
        default:
            die(`unknown subcommand ${sub}`);
    }
}

const invokedAs = process.argv[1] ? pathToFileURL(realpathSync(process.argv[1])).href : "";
if (import.meta.url === invokedAs) main();
