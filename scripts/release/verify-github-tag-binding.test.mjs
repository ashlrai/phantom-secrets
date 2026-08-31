import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const verifier = path.join(repoRoot, "scripts/release/verify-github-tag-binding.mjs");

function git(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-release-tag-"));
  const remote = path.join(root, "remote.git");
  const work = path.join(root, "work");
  fs.mkdirSync(work);
  git(root, "init", "--bare", "-q", remote);
  git(work, "init", "-q");
  git(work, "config", "user.name", "Phantom Release Test");
  git(work, "config", "user.email", "release-test@phm.dev");
  fs.writeFileSync(path.join(work, "fixture.txt"), "first\n");
  git(work, "add", "fixture.txt");
  git(work, "commit", "-qm", "fixture");
  git(work, "remote", "add", "origin", remote);
  return { remote, work, commit: git(work, "rev-parse", "HEAD") };
}

function verify(work, tag, commit) {
  return spawnSync(process.execPath, [verifier, tag, commit, "origin"], {
    cwd: work,
    encoding: "utf8",
  });
}

test("accepts only an annotated remote tag peeled to the expected commit", () => {
  const { work, commit } = fixture();
  git(work, "tag", "-a", "v0.7.3", "-m", "Phantom v0.7.3", commit);
  git(work, "push", "-q", "origin", "refs/tags/v0.7.3");

  const result = verify(work, "v0.7.3", commit);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, new RegExp(commit));
});

test("rejects missing, lightweight, and moved remote tags", () => {
  const missing = fixture();
  assert.notEqual(verify(missing.work, "v0.7.3", missing.commit).status, 0);

  const lightweight = fixture();
  git(lightweight.work, "tag", "v0.7.3", lightweight.commit);
  git(lightweight.work, "push", "-q", "origin", "refs/tags/v0.7.3");
  assert.notEqual(verify(lightweight.work, "v0.7.3", lightweight.commit).status, 0);

  const moved = fixture();
  git(moved.work, "tag", "-a", "v0.7.3", "-m", "Phantom v0.7.3", moved.commit);
  git(moved.work, "push", "-q", "origin", "refs/tags/v0.7.3");
  fs.appendFileSync(path.join(moved.work, "fixture.txt"), "second\n");
  git(moved.work, "add", "fixture.txt");
  git(moved.work, "commit", "-qm", "move tag target");
  const newCommit = git(moved.work, "rev-parse", "HEAD");
  git(moved.work, "tag", "-fa", "v0.7.3", "-m", "Moved tag", newCommit);
  git(moved.work, "push", "-q", "--force", "origin", "refs/tags/v0.7.3");
  assert.notEqual(verify(moved.work, "v0.7.3", moved.commit).status, 0);
});
