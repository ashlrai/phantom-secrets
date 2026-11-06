import assert from "node:assert/strict";
import test from "node:test";
import { unmerged } from "./unmerged-paths.mjs";

test("unmerged queries Git in the requested directory with UTF-8 output", () => {
  let calls = 0;
  assert.deepEqual(unmerged("fixture directory", (command, args, options) => {
    calls++;
    assert.equal(command, "git");
    assert.deepEqual(args, ["ls-files", "-u"]);
    assert.deepEqual(options, { cwd: "fixture directory", encoding: "utf8" });
    return "";
  }), []);
  assert.equal(calls, 1);
});

test("unmerged returns no paths for empty or blank output", () => {
  for (const output of ["", "\n", "\n\n"]) {
    assert.deepEqual(unmerged("fixture", () => output), []);
  }
});

test("unmerged deduplicates nonadjacent stages and sorts nested paths by code unit", () => {
  const paths = ["z.md", "docs/a file.md", "B.md", "é.md", "😀.md", "\uE000.md"];
  const output = [1, 3, 2].flatMap(stage => paths.map(path => `100644 abc ${stage}\t${path}`)).join("\n") + "\n";
  assert.deepEqual(unmerged("fixture", () => output), ["B.md", "docs/a file.md", "z.md", "é.md", "😀.md", "\uE000.md"]);
});

test("unmerged propagates Git failures instead of reporting a clean index", () => {
  const failure = new Error("git ls-files failed");
  assert.throws(() => unmerged("fixture", () => { throw failure; }), error => error === failure);
});
