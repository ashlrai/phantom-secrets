const assert = require("node:assert/strict");
const test = require("node:test");
const { assertClipboardEventuallyEquals } = require("./clipboard-poll.cjs");

test("clipboard assertion waits for an eventual exact match", async () => {
  const values = ["old command", "new command ", "new command"];
  let reads = 0;
  const page = { evaluate: async () => values[reads++] };
  await assertClipboardEventuallyEquals(page, "new command", { timeout: 500, interval: 1 });
  assert.equal(reads, 3);
});

test("clipboard assertion rejects a persistent trailing-space mismatch", async () => {
  const page = { evaluate: async () => "new command " };
  await assert.rejects(
    assertClipboardEventuallyEquals(page, "new command", { timeout: 30, interval: 2 }),
    /Clipboard did not match/,
  );
});

test("clipboard assertion bounds a read that never settles", async () => {
  const page = { evaluate: () => new Promise(() => {}) };
  await assert.rejects(
    assertClipboardEventuallyEquals(page, "new command", { timeout: 30, interval: 2 }),
    /Clipboard did not match/,
  );
});

test("clipboard read errors fail the assertion", async () => {
  const page = { evaluate: async () => { throw new Error("clipboard denied"); } };
  await assert.rejects(assertClipboardEventuallyEquals(page, "new command"), /clipboard denied/);
});
