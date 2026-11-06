const assert = require("node:assert/strict");
const { performance } = require("node:perf_hooks");
const { setTimeout: sleep } = require("node:timers/promises");

// Playwright 1.64.1's waitForFunction treats an async predicate's Promise as truthy.
// Await each clipboard read in Node, including a deadline for a stuck read.
async function assertClipboardEventuallyEquals(page, expected, { timeout = 10000, interval = 100 } = {}) {
  const deadline = performance.now() + timeout;
  const timedOut = Symbol("clipboard read timed out");
  let actual;
  while (performance.now() < deadline) {
    let timer;
    const remaining = deadline - performance.now();
    const result = await Promise.race([
      page.evaluate(() => navigator.clipboard.readText()),
      new Promise((resolve) => { timer = setTimeout(() => resolve(timedOut), Math.max(0, remaining)); }),
    ]).finally(() => clearTimeout(timer));
    if (result === timedOut) break;
    actual = result;
    if (actual === expected) break;
    const delay = Math.min(interval, deadline - performance.now());
    if (delay > 0) await sleep(delay);
  }
  assert.equal(actual, expected, "Clipboard did not match the displayed command before the deadline");
}

module.exports = { assertClipboardEventuallyEquals };
