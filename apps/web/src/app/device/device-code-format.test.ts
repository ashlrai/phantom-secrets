import assert from "node:assert/strict";
import test from "node:test";
import {
  formatDeviceUserCode,
  isValidDeviceUserCode,
  normalizeDeviceUserCode,
} from "../../lib/device-code.ts";

test("eight letters and numbers display as two groups of four", () => {
  for (const input of ["abcd2345", "ABCD-2345", " ab cd-23 45! "]) {
    const displayed = formatDeviceUserCode(input);
    assert.equal(displayed, "ABCD-2345");
    assert.equal(normalizeDeviceUserCode(displayed), "ABCD2345");
    assert.equal(isValidDeviceUserCode(displayed), true);
  }
});

test("partial and overlong codes remain visible and fail validation", () => {
  for (const [input, displayed] of [
    ["", ""],
    ["a", "A"],
    ["abcd", "ABCD"],
    ["abcde", "ABCD-E"],
    ["abcd234", "ABCD-234"],
    ["abcd23456", "ABCD-23456"],
    ["abcd23456789", "ABCD-23456789"],
    ["---", ""],
  ]) {
    assert.equal(formatDeviceUserCode(input), displayed);
    assert.equal(isValidDeviceUserCode(displayed), false, input);
  }
});
