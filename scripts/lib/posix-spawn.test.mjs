import assert from "node:assert/strict";
import test from "node:test";
import { spawnPosixSync } from "./posix-spawn.mjs";

for (const command of ["python3", "bash"]) {
  for (const platform of ["linux", "darwin", "win32"]) {
    test(`${command} uses the expected launcher on ${platform} without changing arguments or options`, () => {
      const args = Object.freeze(["-c", "literal argument with spaces; $()", "--help"]);
      const options = Object.freeze({ cwd: "fixture directory", input: "fixture input", encoding: "utf8" });
      const result = { status: 7, stdout: "fixture output", stderr: "fixture error" };
      let calls = 0;
      const actual = spawnPosixSync(command, args, options, platform, (file, argv, opts) => {
        calls++;
        assert.equal(file, platform === "win32" ? command : "/usr/bin/env");
        assert.deepEqual(argv, platform === "win32" ? args : [command, ...args]);
        assert.equal(opts, options);
        return result;
      });
      assert.equal(calls, 1);
      assert.equal(actual, result);
    });
  }
}

test("spawn errors are returned unchanged", () => {
  const result = { status: null, error: Object.assign(new Error("fixture missing executable"), { code: "ENOENT" }) };
  assert.equal(spawnPosixSync("python3", [], {}, "linux", () => result), result);
});

test("synchronous launcher failures propagate", () => {
  const failure = new Error("fixture launcher failure");
  assert.throws(() => spawnPosixSync("bash", [], {}, "win32", () => { throw failure; }), error => error === failure);
});
