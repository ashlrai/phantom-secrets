import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
    classifyAll,
    codeownersMatch,
    codeownersPatterns,
    codeql,
    CODEQL_LANGUAGES,
    platform,
    suites,
} from "./pr-classify.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PR = "pull_request";

const map = (files) => (f) => files[f] ?? null;
const PLAIN_RS = "fn main() {}\n";
const CFG_RS = "#[cfg(target_os = \"windows\")]\nfn w() {}\n";

const CODEOWNERS = readFileSync(
    join(HERE, "..", "..", ".github", "CODEOWNERS"),
    "utf8",
);

// ---------------------------------------------------------------------------
// ci.yml `classify` step

describe("suites", () => {
    test("non-PR events select rust, web and temporal but not docs_commands", () => {
        assert.deepEqual(suites([], "schedule"), {
            rust: true, web: true, temporal_example: true, docs_commands: false,
        });
        assert.deepEqual(suites([], "merge_group").rust, true);
    });

    test("docs-only PR selects no suite", () => {
        const s = suites(["docs/guide.md", "README.md", "LICENSE"], PR);
        assert.equal(s.rust, false);
        assert.equal(s.web, false);
        assert.equal(s.temporal_example, false);
        // README.md and docs/*.md feed the docs-command check.
        assert.equal(s.docs_commands, true);
    });

    test("web-only diff selects web but not rust", () => {
        const s = suites(["apps/web/src/app/page.tsx"], PR);
        assert.equal(s.web, true);
        assert.equal(s.rust, false);
    });

    test("rust/web overlap: crates change selects rust only", () => {
        const s = suites(["crates/phantom-vault/src/lib.rs"], PR);
        assert.equal(s.rust, true);
        assert.equal(s.web, false);
    });

    test("workflow changes select rust, web and temporal", () => {
        const s = suites([".github/workflows/ci.yml"], PR);
        assert.equal(s.rust, true);
        assert.equal(s.web, true);
        assert.equal(s.temporal_example, true);
        assert.equal(s.docs_commands, true);
    });

    test("temporal example path selects only that suite plus rust", () => {
        const s = suites(["examples/temporal-codec-python/server.py"], PR);
        assert.equal(s.temporal_example, true);
        assert.equal(s.rust, true); // non-docs, non-web-only
    });
});

// ---------------------------------------------------------------------------
// ci.yml `platform` step

describe("platform", () => {
    const base = { event: PR, files: ["docs/guide.md"], readFile: map({}) };

    test("non-PR events always select the full matrix", () => {
        assert.equal(platform({ event: "schedule", files: [] }).platform, true);
        assert.equal(platform({ event: "merge_group", files: [] }).platform, true);
    });

    test("ci:full-os and full-ci labels both select the matrix (#547 alias)", () => {
        for (const l of ["ci:full-os", "full-ci"]) {
            assert.equal(platform({ ...base, labels: [l] }).platform, true, l);
        }
        assert.equal(platform({ ...base, labels: ["other"] }).platform, false);
    });

    test("docs-only diff does not select the matrix", () => {
        assert.equal(platform({ event: PR, files: ["docs/a.md"], readFile: map({}) }).platform, false);
    });

    test("platform-relevant paths select the matrix", () => {
        for (const f of [
            "Cargo.toml", "crates/x/Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
            ".cargo/config.toml", ".github/workflows/ci.yml", "scripts/install.sh",
            "scripts/release/publish.mjs", "npm/package.json", "npm-mcp/index.js",
            "apps/web/public/install.ps1", "crates/x/src/windows/mod.rs",
            "tools/unix/daemon.sh", "scripts/platform/install.mjs",
        ]) {
            assert.equal(platform({ event: PR, files: [f], readFile: map({}) }).platform, true, f);
        }
    });

    test("a .rs change with OS-gated cfg selects the matrix", () => {
        const files = ["crates/x/src/lib.rs"];
        assert.equal(
            platform({ event: PR, files, readFile: map({ "crates/x/src/lib.rs": CFG_RS }) }).platform,
            true,
        );
        assert.equal(
            platform({ event: PR, files, readFile: map({ "crates/x/src/lib.rs": PLAIN_RS }) }).platform,
            false,
        );
    });

    test("an unreadable .rs fails closed to platform-relevant", () => {
        // readFile returns null: the file was deleted or cannot be opened.
        assert.equal(
            platform({ event: PR, files: ["crates/x/src/gone.rs"], readFile: map({}) }).platform,
            true,
        );
    });

    test("an unreadable diff fails closed to the full matrix", () => {
        assert.equal(platform({ event: PR, files: null }).platform, true);
    });
});

// ---------------------------------------------------------------------------
// Tier-1 CODEOWNERS matching (#547's reviewed awk, ported)

describe("codeowners", () => {
    test("the repository's own CODEOWNERS parses to anchored patterns", () => {
        const pats = codeownersPatterns(CODEOWNERS);
        assert.ok(pats.length > 10);
        assert.ok(pats.every((p) => p.mode === "root"), "every entry is /-anchored");
        // Glob is cut to its literal prefix.
        assert.ok(pats.some((p) => p.pre === "crates/phantom-core/src/team_crypto"));
    });

    test("Tier-1 owned paths select the matrix via platform()", () => {
        for (const f of [
            ".github/workflows/release.yml",
            "crates/phantom-vault/src/lib.rs",
            "crates/phantom-core/src/cloud_http.rs",
            "crates/phantom-core/src/team_crypto_xwing.rs",
            "apps/web/src/lib/auth.ts",
            "apps/web/supabase/migrations/001_init.sql",
            ".github/tests/secret-shape/scrub.pl",
        ]) {
            assert.equal(
                platform({ event: PR, files: [f], readFile: () => PLAIN_RS, codeownersText: CODEOWNERS }).platform,
                true,
                f,
            );
        }
    });

    test("unowned paths do not match CODEOWNERS", () => {
        assert.equal(codeownersMatch(["docs/guide.md", "scripts/ci/daily-matrix.mjs"], CODEOWNERS), false);
        assert.equal(codeownersMatch(["crates/phantom-cli/src/main.rs"], CODEOWNERS), false);
    });

    test("root / seg / sub modes and the bare-star rule", () => {
        const text = [
            "# comment",
            "",
            "/src/secure/ @a",     // root: repo-root prefix only
            "LICENSE @a",          // seg: path segment at any depth
            "*.rs @a",             // sub: suffix-style substring
            "vendor/ @b",          // seg: dir name at any depth
        ].join("\n");
        assert.equal(codeownersMatch(["src/secure/k.c"], text), true);
        assert.equal(codeownersMatch(["other/src/secure/k.c"], text), false); // anchored
        assert.equal(codeownersMatch(["docs/LICENSE"], text), true);
        assert.equal(codeownersMatch(["x/y.rs"], text), true); // *.rs kept
        assert.equal(codeownersMatch(["third_party/vendor/lib.c"], text), true);
        assert.equal(codeownersMatch(["plain.txt"], text), false);
        assert.equal(codeownersMatch(["anything"], "* @a"), true); // bare * owns all
        assert.equal(codeownersMatch([], "* @a"), false); // no files, no match
    });

    test("patterns starting with * stay suffix matches", () => {
        assert.equal(codeownersMatch(["a/b/package.json"], "**/package.json @a"), true);
        assert.equal(codeownersMatch(["src/gen.c"], "*.c @a"), true);
        // The reviewed awk keeps a loose substring for *-patterns: *.c also
        // matches .cpp (over-selects coverage; safe direction).
        assert.equal(codeownersMatch(["src/gen.cpp"], "*.c @a"), true);
        assert.equal(codeownersMatch(["src/gen.py"], "*.c @a"), false);
    });
});

// ---------------------------------------------------------------------------
// codeql.yml `classify` step

describe("codeql", () => {
    test("non-PR events scan every language", () => {
        assert.deepEqual(codeql([], "push").languages, CODEQL_LANGUAGES);
        assert.deepEqual(codeql([], "merge_group").languages, CODEQL_LANGUAGES);
        assert.deepEqual(codeql([], "schedule").code, true);
    });

    test("an unreadable diff scans every language", () => {
        assert.deepEqual(codeql(null, PR).languages, CODEQL_LANGUAGES);
        assert.equal(codeql(null, PR).code, true);
    });

    test("docs-only PR scans nothing", () => {
        assert.deepEqual(codeql(["docs/a.md", "README.md"], PR), { code: false, languages: [] });
    });

    test("per-language selection", () => {
        assert.deepEqual(codeql(["crates/x/src/lib.rs"], PR).languages, ["rust"]);
        assert.deepEqual(codeql(["scripts/installers.test.js"], PR).languages, ["javascript-typescript"]);
        assert.deepEqual(codeql(["examples/temporal-codec-python/server.py"], PR).languages, ["python"]);
        assert.deepEqual(codeql(["ci-actions/deploy/action.yml"], PR).languages, ["actions"]);
        assert.deepEqual(codeql(["lib/tasks/release.rake"], PR).languages, ["ruby"]);
        const multi = codeql(["a.rs", "b.py", "c.js"], PR).languages;
        assert.deepEqual(multi, ["javascript-typescript", "python", "rust"]);
    });

    test(".github or build/dependency config scans every language (#547 allcfg)", () => {
        for (const f of [
            ".github/CODEOWNERS", ".github/dependabot.yml",
            ".github/workflows/ci.yml", ".github/tests/secret-shape/scrub.pl",
            ".cargo/config.toml", "Cargo.toml", "crates/x/Cargo.lock",
            "rust-toolchain.toml", "crates/x/build.rs",
            "npm/package-lock.json", "npm-shrinkwrap.json",
            "apps/web/tsconfig.json", "pyproject.toml",
            "requirements-dev.txt", "Gemfile.lock", "foo.gemspec",
        ]) {
            assert.deepEqual(codeql([f], PR).languages, CODEQL_LANGUAGES, f);
        }
    });

    test("language set feeds a JSON matrix unchanged", () => {
        const { languages } = codeql(["src/lib.rs"], PR);
        assert.deepEqual(JSON.parse(JSON.stringify(languages)), ["rust"]);
    });

    test("a non-code, non-config change skips analysis", () => {
        assert.deepEqual(codeql(["video/demo.mp4"], PR), { code: false, languages: [] });
    });
});

// ---------------------------------------------------------------------------
// Combined classifyAll contract

describe("classifyAll", () => {
    test("non-PR event emits the full surface", () => {
        assert.deepEqual(classifyAll({ event: "schedule", files: [] }), {
            rust: true, web: true, temporal_example: true, docs_commands: false,
            platform: true, code: true, languages: CODEQL_LANGUAGES,
        });
    });

    test("unreadable PR diff emits every output at full coverage", () => {
        assert.deepEqual(classifyAll({ event: PR, files: null }), {
            rust: true, web: true, temporal_example: true, docs_commands: true,
            platform: true, code: true, languages: CODEQL_LANGUAGES,
        });
    });

    test("docs-only PR emits the minimal surface", () => {
        const out = classifyAll({ event: PR, files: ["docs/a.md"], readFile: map({}) });
        assert.deepEqual(out, {
            rust: false, web: false, temporal_example: false, docs_commands: true,
            platform: false, code: false, languages: [],
        });
    });

    test("output names match the workflow contract exactly", () => {
        const keys = Object.keys(classifyAll({ event: PR, files: ["a.rs"], readFile: map({ "a.rs": PLAIN_RS }) }));
        assert.deepEqual(keys.sort(), [
            "code", "docs_commands", "languages", "platform",
            "rust", "temporal_example", "web",
        ]);
    });
});
