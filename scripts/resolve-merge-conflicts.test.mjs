import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const helper = join(repoRoot, "scripts", "resolve-merge-conflicts.sh");

const hasCargo = spawnSync("cargo", ["--version"]).status === 0;

function git(dir, ...args) {
    return execFileSync("git", args, { cwd: dir, encoding: "utf8" });
}

function tryGit(dir, ...args) {
    return spawnSync("git", args, { cwd: dir, encoding: "utf8" });
}

function write(dir, name, text) {
    writeFileSync(join(dir, name), text);
}

function unmerged(dir) {
    return [...new Set(git(dir, "ls-files", "-u").trim().split("\n")
        .filter(Boolean).map((l) => l.split("\t")[1]))].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function longDoc(tag) {
    const lines = [`# ${tag}`, ""];
    for (let i = 1; i <= 20; i++) lines.push(`filler line ${i}`);
    lines.splice(3, 0, "alpha-original");
    lines.splice(23, 0, "bravo-original");
    return lines.join("\n") + "\n";
}

function changelog(entry) {
    return [
        "# Changelog",
        "",
        "## [Unreleased]",
        "",
        entry,
        "",
        "## [0.1.0] - 2026-01-01",
        "",
        "- initial release",
        "",
    ].join("\n");
}

const CARGO_TOML = (v) => `[package]\nname = "conflict-fixture"\nversion = "${v}"\nedition = "2021"\n`;

function initRepo() {
    const dir = mkdtempSync(join(tmpdir(), "mr-conflict-"));
    git(dir, "init", "-q", "-b", "main");
    git(dir, "config", "user.name", "fixture");
    git(dir, "config", "user.email", "fixture@example.com");
    git(dir, "config", "commit.gpgsign", "false");
    return dir;
}

// Base tree: the real .gitattributes (union driver), a changelog, the two doc
// files, and a zero-dependency Cargo package whose lockfile cargo regenerates
// offline.
function seedBase(dir) {
    write(dir, ".gitattributes", readFileSync(join(repoRoot, ".gitattributes"), "utf8"));
    write(dir, "CHANGELOG.md", changelog(""));
    write(dir, "CLAUDE.md", longDoc("CLAUDE"));
    write(dir, "README.md", longDoc("README"));
    write(dir, "Cargo.toml", CARGO_TOML("0.1.0"));
    mkdirSync(join(dir, "src"));
    write(dir, join("src", "lib.rs"), "");
    git(dir, "add", "-A");
    git(dir, "commit", "-qm", "base");
    execFileSync("cargo", ["generate-lockfile"], { cwd: dir });
    git(dir, "add", "Cargo.lock");
    git(dir, "commit", "-qm", "lockfile");
}

// Lane commit: same-line changelog entry, an alpha hunk main will collide
// with, a distant bravo hunk it will not, and a manifest+lockfile bump with a
// bogus package entry no regeneration may keep.
function laneChanges(dir) {
    write(dir, "CHANGELOG.md", changelog("- lane entry"));
    for (const doc of ["CLAUDE.md", "README.md"]) {
        write(dir, doc, readFileSync(join(dir, doc), "utf8")
            .replace("alpha-original", `alpha-lane-${doc}`)
            .replace("bravo-original", `bravo-lane-${doc}`));
    }
    write(dir, "Cargo.toml", CARGO_TOML("0.2.0"));
    write(dir, "Cargo.lock", readFileSync(join(dir, "Cargo.lock"), "utf8")
        .replace('version = "0.1.0"', 'version = "0.2.0"')
        + '\n[[package]]\nname = "ghost"\nversion = "9.9.9"\n');
    git(dir, "commit", "-qam", "lane changes");
}

function upstreamChanges(dir) {
    write(dir, "CHANGELOG.md", changelog("- upstream entry"));
    for (const doc of ["CLAUDE.md", "README.md"]) {
        write(dir, doc, readFileSync(join(dir, doc), "utf8")
            .replace("alpha-original", `alpha-upstream-${doc}`));
    }
    write(dir, "Cargo.lock", readFileSync(join(dir, "Cargo.lock"), "utf8")
        .replace('version = "0.1.0"', 'version = "0.1.1"'));
    git(dir, "commit", "-qam", "upstream changes");
}

test("rebase resolves CHANGELOG union, doc reapply, and Cargo.lock regen", { skip: !hasCargo }, () => {
    const dir = initRepo();
    seedBase(dir);
    git(dir, "checkout", "-qb", "lane");
    laneChanges(dir);
    git(dir, "checkout", "-q", "main");
    upstreamChanges(dir);
    git(dir, "checkout", "-q", "lane");

    const rebase = tryGit(dir, "rebase", "main");
    assert.notEqual(rebase.status, 0, `rebase should stop on conflicts: ${rebase.stderr}`);

    // The union driver settles CHANGELOG.md before any helper runs; the rest
    // stay unmerged.
    assert.deepEqual(unmerged(dir), ["CLAUDE.md", "Cargo.lock", "README.md"]);

    const run = spawnSync("bash", [helper], { cwd: dir, encoding: "utf8" });
    assert.equal(run.status, 0, `helper failed: ${run.stderr}`);
    assert.deepEqual(unmerged(dir), []);

    const cont = tryGit(dir, "-c", "core.editor=true", "rebase", "--continue");
    assert.equal(cont.status, 0, `rebase --continue failed: ${cont.stderr}`);

    // CHANGELOG.md kept both entries, no markers.
    const log = readFileSync(join(dir, "CHANGELOG.md"), "utf8");
    assert.match(log, /- lane entry/);
    assert.match(log, /- upstream entry/);
    assert.doesNotMatch(log, /^<{7}|^={7}|^>{7}/m);

    // Docs: upstream's version of the colliding hunk wins; the lane's
    // non-colliding hunk still lands.
    for (const doc of ["CLAUDE.md", "README.md"]) {
        const text = readFileSync(join(dir, doc), "utf8");
        assert.match(text, new RegExp(`alpha-upstream-${doc}`), doc);
        assert.match(text, new RegExp(`bravo-lane-${doc}`), doc);
        assert.doesNotMatch(text, new RegExp(`alpha-lane-${doc}`), doc);
        assert.doesNotMatch(text, /^<{7}/m, doc);
    }

    // Cargo.lock: regenerated from the lane's manifest (0.2.0); neither the
    // upstream edit nor the lane's bogus ghost entry survived.
    const lock = readFileSync(join(dir, "Cargo.lock"), "utf8");
    assert.match(lock, /name = "conflict-fixture"\nversion = "0\.2\.0"/);
    assert.doesNotMatch(lock, /ghost|0\.1\.1|^<{7}/m);
    assert.match(readFileSync(join(dir, "Cargo.toml"), "utf8"), /version = "0\.2\.0"/);

    // Idempotent on a clean tree.
    const again = spawnSync("bash", [helper], { cwd: dir, encoding: "utf8" });
    assert.equal(again.status, 0, again.stderr);
});

// Leaves a repo mid-merge with README.md unmerged: the lane's alpha hunk
// collides with upstream's (it is rejected into README.md.rej on reapply)
// while the lane's bravo hunk still applies cleanly.
function readmeConflictRepo() {
    const dir = initRepo();
    write(dir, "README.md", longDoc("README"));
    git(dir, "add", "-A");
    git(dir, "commit", "-qm", "base");
    git(dir, "checkout", "-qb", "lane");
    write(dir, "README.md", readFileSync(join(dir, "README.md"), "utf8")
        .replace("alpha-original", "alpha-lane-README.md")
        .replace("bravo-original", "bravo-lane-README.md"));
    git(dir, "commit", "-qam", "lane changes");
    git(dir, "checkout", "-q", "main");
    write(dir, "README.md", readFileSync(join(dir, "README.md"), "utf8")
        .replace("alpha-original", "alpha-upstream-README.md"));
    git(dir, "commit", "-qam", "upstream changes");
    git(dir, "checkout", "-q", "lane");

    // `git merge main` while on the lane: theirs (stage 3) is upstream.
    assert.notEqual(tryGit(dir, "merge", "main").status, 0);
    assert.deepEqual(unmerged(dir), ["README.md"]);
    return dir;
}

// Runs the helper with a stub tool prepended to PATH.
function runWithStub(dir, name, body) {
    const stub = mkdtempSync(join(tmpdir(), "mr-stub-"));
    writeFileSync(join(stub, name), `#!/bin/sh\n${body}`, { mode: 0o755 });
    return spawnSync("bash", [helper], {
        cwd: dir,
        encoding: "utf8",
        env: { ...process.env, PATH: `${stub}:${process.env.PATH}` },
    });
}

test("merge direction: upstream stage 3, lane stage 2", () => {
    const dir = readmeConflictRepo();

    const run = spawnSync("bash", [helper], { cwd: dir, encoding: "utf8" });
    assert.equal(run.status, 0, `helper failed: ${run.stderr}`);

    const text = readFileSync(join(dir, "README.md"), "utf8");
    assert.match(text, /alpha-upstream-README\.md/);
    assert.match(text, /bravo-lane-README\.md/);
    assert.doesNotMatch(text, /alpha-lane-README\.md|^<{7}/m);
});

test("paths outside the managed set stay conflicted and exit 1", () => {
    const dir = initRepo();
    write(dir, "notes.txt", "base\n");
    git(dir, "add", "-A");
    git(dir, "commit", "-qm", "base");
    git(dir, "checkout", "-qb", "lane");
    write(dir, "notes.txt", "lane\n");
    git(dir, "commit", "-qam", "lane");
    git(dir, "checkout", "-q", "main");
    write(dir, "notes.txt", "upstream\n");
    git(dir, "commit", "-qam", "upstream");
    git(dir, "checkout", "-q", "lane");

    assert.notEqual(tryGit(dir, "rebase", "main").status, 0);
    assert.deepEqual(unmerged(dir), ["notes.txt"]);

    const run = spawnSync("bash", [helper], { cwd: dir, encoding: "utf8" });
    assert.equal(run.status, 1);
    assert.match(run.stderr, /notes\.txt/);
    assert.deepEqual(unmerged(dir), ["notes.txt"]);
});

// A grep that dies with exit 2 while counting rejects is a real error, not a
// zero count: `|| true` used to mask it and report a clean resolve.
test("a grep error counting rejects stays conflicted instead of resolving", () => {
    const dir = readmeConflictRepo();

    const run = runWithStub(dir, "grep", "exit 2");
    assert.equal(run.status, 1, `expected failure: ${run.stdout}${run.stderr}`);
    assert.match(run.stderr, /could not count rejected hunks/);
    assert.match(run.stderr, /README\.md/);
    assert.doesNotMatch(run.stdout, /all conflicts resolved/);
    assert.deepEqual(unmerged(dir), ["README.md"]);
});

// A `git apply` that fails without writing a reject file must surface too;
// `|| true` used to stage the bare upstream blob and call it resolved.
test("a git apply failure without rejects stays conflicted", () => {
    const dir = readmeConflictRepo();
    const realGit = execFileSync("which", ["git"], { encoding: "utf8" }).trim();

    const run = runWithStub(dir, "git",
        `[ "$1" = apply ] && exit 2\nexec "${realGit}" "$@"`);
    assert.equal(run.status, 1, `expected failure: ${run.stdout}${run.stderr}`);
    assert.match(run.stderr, /failed without leaving rejects/);
    assert.match(run.stderr, /README\.md/);
    assert.doesNotMatch(run.stdout, /all conflicts resolved/);
    assert.deepEqual(unmerged(dir), ["README.md"]);
});
