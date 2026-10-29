#!/usr/bin/env node
// Compute every changed-file classification ci.yml and codeql.yml need, in one
// tested engine. See scripts/ci/pr-classify.md for the design and the
// G1-gated workflow patch this powers (reworks #547 on the post-diet main:
// `.github/` is not touched by this change).
//
// Outputs (printed as key=value, optionally appended to $GITHUB_OUTPUT):
//   rust, web, temporal_example, docs_commands   ci.yml `classify` step
//   platform                                     ci.yml `platform` step
//   code, languages                              codeql.yml `classify` step
//
// Usage:
//   node scripts/ci/pr-classify.mjs [classify] [opts]
//
// Input opts:
//   --event NAME         github.event_name (default $EVENT, else pull_request)
//   --base SHA           diff BASE...HEAD for the changed-file list
//   --head SHA           diff head (default HEAD)
//   --files PATH|-       newline-separated changed paths ('-' reads stdin);
//                        overrides --base/--head
//   --labels a,b,c       pull_request label names (default $LABELS)
//   --codeowners PATH    CODEOWNERS text for Tier-1 matching; the default
//                        (pull_request + --base) is `git show BASE:.github/CODEOWNERS`.
//                        A missing/unreadable CODEOWNERS only skips Tier-1.
//   --github-output      append every output to $GITHUB_OUTPUT
//   --explain            print per-output reasons to stderr
//
// Every rule fails closed toward MORE coverage: an unreadable diff selects
// every suite, the full OS matrix, and every CodeQL language; an unreadable
// .rs marks the diff platform-relevant; a missing CODEOWNERS merely removes a
// trigger that can only widen coverage.

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const CODEQL_LANGUAGES = [
    "actions",
    "javascript-typescript",
    "python",
    "ruby",
    "rust",
];

// ---------------------------------------------------------------------------
// ci.yml `classify` step: which suites the diff can affect. Each regex is the
// exact expression the workflow's inline bash uses today; keeping them here
// makes them unit-testable.

// Docs-only surfaces that never select a suite.
const CLASSIFY_DOCS_RE =
    /^(docs\/|[^/]*\.md$|.*\/README\.md$|LICENSE|\.github\/ISSUE_TEMPLATE\/|\.github\/PULL_REQUEST_TEMPLATE)/;
// Surfaces exercised only by the web job; a docs-or-web-only PR selects no
// Rust suite.
const WEB_ONLY_RE = /^(apps\/web\/|scripts\/supabase\/|scripts\/seo\/|video\/)/;
const WEB_RE = /^(apps\/web\/|scripts\/supabase\/|scripts\/seo\/|\.github\/workflows\/)/;
const TEMPORAL_RE = /^(examples\/temporal-codec-python\/|\.github\/workflows\/)/;
const DOCS_COMMANDS_RE =
    /^(README\.md$|docs\/[^/]+\.md$|apps\/web\/src\/|apps\/web\/public\/llms[^/]*\.txt$|\.github\/workflows\/)/;
const CI_RE = /^\.github\/workflows\//;

export function suites(files, event) {
    if (event !== "pull_request") {
        return { rust: true, web: true, temporal_example: true, docs_commands: false };
    }
    const rust = files.some((f) => !CLASSIFY_DOCS_RE.test(f) && !WEB_ONLY_RE.test(f))
        || files.some((f) => CI_RE.test(f));
    return {
        rust,
        web: files.some((f) => WEB_RE.test(f)),
        temporal_example: files.some((f) => TEMPORAL_RE.test(f)),
        docs_commands: files.some((f) => DOCS_COMMANDS_RE.test(f)),
    };
}

// ---------------------------------------------------------------------------
// ci.yml `platform` step: does the diff need the macOS/Windows Test legs?
// `ci:full-os` and `full-ci` are aliases (#547). Tier-1 owned paths — any
// pattern in the base ref's .github/CODEOWNERS — also select the matrix.

export const FULL_OS_LABELS = new Set(["ci:full-os", "full-ci"]);

// Platform-relevant paths: OS-gated Rust, build/toolchain config, installers,
// npm wrappers, CI itself. Same expression as the workflow's inline bash.
const PLATFORM_PATH_RE =
    /(^|\/)(Cargo\.toml|Cargo\.lock|rust-toolchain(\.toml)?|build\.rs)$|^\.cargo\/|^\.github\/workflows\/|^scripts\/(install\.(sh|ps1)|check-platform-installers\.mjs|installers\.test\.js|release\/)|^npm(-mcp)?\/|^apps\/web\/public\/install\.|(^|\/)(windows|macos|unix|platform)[^/]*(\/|\.rs$)/;
// OS-gated cfg expressions inside a changed .rs file.
const OS_CFG_RE =
    /cfg\((not\()?(windows|unix|target_os|target_family)|cfg!\((windows|unix|target_os)/;

/**
 * CODEOWNERS matching, ported from #547's reviewed awk. Each pattern takes a
 * mode: leading `*` -> substring anywhere; leading `/` or a mid-pattern `/` ->
 * anchored at the repo root; otherwise a path-segment match at any depth.
 * Leading `*`/`/` are stripped and the pattern is cut at the next `*`, so
 * `/team_crypto*.rs` anchors the literal prefix and a bare `*` owns every
 * path. Blank lines, comments and non-pattern fields are skipped.
 */
export function codeownersPatterns(text) {
    const out = [];
    for (const line of text.split("\n")) {
        const t = line.trim();
        if (!t || t.startsWith("#")) continue;
        const pat = t.split(/\s+/)[0];
        let mode = "seg";
        if (pat.startsWith("*")) mode = "sub";
        else if (pat.startsWith("/") || /.\/.+/.test(pat)) mode = "root";
        // Strip leading / and * chars (so **/x and *.rs keep a suffix match),
        // then cut at the next *: the kept prefix is a literal path fragment.
        const pre = pat.replace(/^[*/]+/, "").split("*")[0];
        out.push({ mode, pre });
    }
    return out;
}

export function codeownersMatch(files, codeownersText) {
    const pats = codeownersPatterns(codeownersText);
    if (!pats.length || !files.length) return false;
    for (const { mode, pre } of pats) {
        if (!pre) return true; // a bare * (or **) owns every path
        for (const f of files) {
            if (mode === "root" && f.startsWith(pre)) return true;
            if (mode === "seg" && `/${f}`.includes(`/${pre}`)) return true;
            if (mode === "sub" && f.includes(pre)) return true;
        }
    }
    return false;
}

/**
 * `readFile(path)` returns file contents or null when unreadable/deleted; an
 * unreadable .rs fails closed to platform-relevant (the inline bash today
 * silently skips it). `labels` is a Set or array of PR label names.
 */
export function platform({ event, labels = [], files, codeownersText = null, readFile = () => null }) {
    const why = [];
    const yes = (reason) => { why.push(reason); return { platform: true, why }; };
    if (event !== "pull_request") return yes("non-PR event runs every leg");
    const names = new Set(labels);
    for (const l of FULL_OS_LABELS) if (names.has(l)) return yes(`label ${l}`);
    if (files === null) return yes("unreadable diff: fail closed to the full matrix");
    for (const f of files) {
        if (PLATFORM_PATH_RE.test(f)) return yes(`platform path ${f}`);
    }
    if (codeownersText !== null && codeownersMatch(files, codeownersText)) {
        return yes("Tier-1 owned path (CODEOWNERS)");
    }
    for (const f of files) {
        if (!f.endsWith(".rs")) continue;
        const body = readFile(f);
        if (body === null) return yes(`unreadable .rs ${f}: fail closed`);
        if (OS_CFG_RE.test(body)) return yes(`OS-gated cfg in ${f}`);
    }
    return { platform: false, why: ["no platform-relevant input"] };
}

// ---------------------------------------------------------------------------
// codeql.yml `classify` step: which languages a PR scans. Beyond today's
// per-language selection (#811 pattern) this carries #547's hardening: any
// `.github/` or build/dependency-config change scans every language, and an
// unreadable diff fails closed to the full set.

const CODEQL_DOCS_RE =
    /^(docs\/|.*\.md$|LICENSE|\.github\/ISSUE_TEMPLATE\/|\.github\/PULL_REQUEST_TEMPLATE)/;
// Build/dependency/CI configuration whose semantics cross language lines:
// a change here can alter what every scan sees, so all five languages scan.
const ALL_CONFIG_RE =
    /^\.github\/|^\.cargo\/|(^|\/)(Cargo\.(toml|lock)|rust-toolchain(\.toml)?|build\.rs|package(-lock)?\.json|npm-shrinkwrap\.json|tsconfig[^/]*\.json|pyproject\.toml|requirements[^/]*\.txt|Gemfile(\.lock)?|[^/]*\.gemspec)$/;
const LANGUAGE_RES = [
    ["actions", /^\.github\/(workflows|actions)\/|(^|\/)action\.ya?ml$/],
    ["javascript-typescript", /\.(js|jsx|mjs|cjs|ts|tsx|mts|cts|vue|svelte|astro|html?)$|(^|\/)package(-lock)?\.json$/],
    ["python", /\.(py|pyi)$|(^|\/)(requirements[^/]*\.txt|pyproject\.toml|setup\.(py|cfg))$/],
    ["ruby", /\.(rb|erb|gemspec|rake)$|(^|\/)(Gemfile(\.lock)?|Rakefile)$/],
    ["rust", /\.rs$|(^|\/)Cargo\.(toml|lock)$|(^|\/)rust-toolchain(\.toml)?$/],
];

export function codeql(files, event) {
    if (event !== "pull_request") {
        return { code: true, languages: [...CODEQL_LANGUAGES] };
    }
    if (files === null) {
        return { code: true, languages: [...CODEQL_LANGUAGES] }; // fail closed
    }
    const codePaths = files.filter((f) => !CODEQL_DOCS_RE.test(f));
    if (codePaths.some((f) => ALL_CONFIG_RE.test(f))) {
        return { code: true, languages: [...CODEQL_LANGUAGES] };
    }
    const langs = new Set();
    for (const [lang, re] of LANGUAGE_RES) {
        if (codePaths.some((f) => re.test(f))) langs.add(lang);
    }
    // No scannable language -> the Analyze job is skipped, matching the
    // workflow's code=false contract.
    if (!langs.size) return { code: false, languages: [] };
    return { code: true, languages: CODEQL_LANGUAGES.filter((l) => langs.has(l)) };
}

// ---------------------------------------------------------------------------
// Combined classification + CLI.

export function classifyAll({ event, labels, files, codeownersText, readFile }) {
    if (event !== "pull_request") {
        return {
            ...suites([], event),
            platform: true,
            ...codeql(null, event),
        };
    }
    if (files === null) {
        // Unreadable diff: every suite, the full matrix, every language.
        return {
            rust: true, web: true, temporal_example: true, docs_commands: true,
            platform: true, code: true, languages: [...CODEQL_LANGUAGES],
        };
    }
    const p = platform({ event, labels, files, codeownersText, readFile });
    return { ...suites(files, event), platform: p.platform, ...codeql(files, event) };
}

function gitDiffNames(base, head) {
    const out = execFileSync("git", ["-c", "core.quotepath=off", "diff", "--name-only", `${base}...${head}`], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
    });
    return out.split("\n").filter(Boolean);
}

function gitShowBase(base, path) {
    try {
        return execFileSync("git", ["show", `${base}:${path}`], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    } catch {
        return null;
    }
}

function die(msg) {
    process.stderr.write(`pr-classify: ${msg}\n`);
    process.exit(2);
}

function parseArgs(argv) {
    const opts = {
        event: process.env.EVENT || "pull_request",
        base: process.env.BASE || null,
        head: process.env.HEAD || "HEAD",
        files: null,
        labels: process.env.LABELS || "",
        codeowners: undefined, // undefined: default base-ref lookup; null: disabled
        githubOutput: false,
        explain: false,
    };
    const rest = [...argv];
    let sub = "classify";
    if (rest[0] && !rest[0].startsWith("-")) sub = rest.shift();
    while (rest.length) {
        const a = rest.shift();
        switch (a) {
            case "--event": opts.event = rest.shift() ?? die("--event needs a value"); break;
            case "--base": opts.base = rest.shift() ?? die("--base needs a value"); break;
            case "--head": opts.head = rest.shift() ?? die("--head needs a value"); break;
            case "--files": opts.files = rest.shift() ?? die("--files needs a value"); break;
            case "--labels": opts.labels = rest.shift() ?? die("--labels needs a value"); break;
            case "--codeowners": opts.codeowners = rest.shift() ?? die("--codeowners needs a value"); break;
            case "--no-codeowners": opts.codeowners = null; break;
            case "--github-output": opts.githubOutput = true; break;
            case "--explain": opts.explain = true; break;
            case "--help": case "-h": sub = "help"; break;
            default: die(`unknown argument ${a}`);
        }
    }
    return { opts, sub };
}

function usage() {
    process.stdout.write(
        `pr-classify.mjs — every PR classification ci.yml and codeql.yml need

  classify  [opts]   emit rust/web/temporal_example/docs_commands/platform/code/languages (default)

Opts: --event NAME --base SHA [--head SHA] | --files PATH|-
      --labels a,b,c --codeowners PATH | --no-codeowners
      --github-output --explain --help
`,
    );
}

function emit(outputs, { githubOutput }) {
    const lines = Object.entries(outputs).map(([k, v]) =>
        `${k}=${typeof v === "boolean" ? v : JSON.stringify(v)}`);
    process.stdout.write(`${lines.join("\n")}\n`);
    if (githubOutput) {
        const target = process.env.GITHUB_OUTPUT;
        if (!target) die("--github-output needs $GITHUB_OUTPUT");
        appendFileSync(target, `${lines.join("\n")}\n`);
    }
}

function main() {
    const { opts, sub } = parseArgs(process.argv.slice(2));
    if (sub === "help") return usage();
    if (sub !== "classify") die(`unknown subcommand ${sub}`);

    const root = process.cwd();
    const readFile = (f) => {
        try { return readFileSync(join(root, f), "utf8"); } catch { return null; }
    };

    let files = null;
    if (opts.event === "pull_request") {
        if (opts.files !== null) {
            try {
                files = (opts.files === "-"
                    ? readFileSync(0, "utf8")
                    : readFileSync(opts.files, "utf8")).split("\n").filter(Boolean);
            } catch (e) {
                die(`cannot read --files ${opts.files}: ${e.code ?? e.message}`);
            }
        } else if (opts.base) {
            try {
                files = gitDiffNames(opts.base, opts.head);
            } catch {
                process.stderr.write("::warning::diff unreadable; selecting full coverage\n");
                files = null; // fail closed: every output selects full coverage
            }
        } else {
            die("pull_request classification needs --files or --base");
        }
    }

    let codeownersText = null;
    if (opts.event === "pull_request") {
        if (typeof opts.codeowners === "string") {
            try { codeownersText = readFileSync(opts.codeowners, "utf8"); }
            catch { codeownersText = null; }
        } else if (opts.codeowners === undefined && opts.base) {
            codeownersText = gitShowBase(opts.base, ".github/CODEOWNERS");
        }
    }

    const labels = opts.labels ? opts.labels.split(",").map((l) => l.trim()).filter(Boolean) : [];
    const outputs = classifyAll({ event: opts.event, labels, files, codeownersText, readFile });

    if (opts.explain) {
        const p = opts.event === "pull_request" && files !== null
            ? platform({ event: opts.event, labels, files, codeownersText, readFile })
            : { why: ["non-PR event or unreadable diff: full coverage"] };
        process.stderr.write(
            `files=${files === null ? "(unreadable)" : files.length} labels=[${labels.join(",")}]\n` +
            `platform: ${p.why.join("; ")}\n`,
        );
    }
    emit(outputs, opts);
}

const invokedAs = process.argv[1] ? pathToFileURL(realpathSync(process.argv[1])).href : "";
if (import.meta.url === invokedAs) main();
