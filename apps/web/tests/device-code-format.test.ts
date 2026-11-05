// This test file delegates to the CommonJS implementation in device-code-format.test.cjs
// which uses ts.transpileModule to compile the React component and can resolve npm
// packages. Node.js --experimental-strip-types does not resolve npm packages from .ts
// files in this directory without "type": "module" in package.json, which would break
// the existing .cjs test suite (570+ tests). The companion .cjs file runs through the
// npm test script via the tests/*.test.cjs glob.
//
// Device code format validation:
// - isValidDeviceUserCode("") returns false (empty string normalizes to length 0)
// - formatDeviceUserCode("") returns "" (empty remains empty)
// - handleSubmit rejects empty codes with a validation error before any submission
//
// See device-code-format.test.cjs for the full behavioral test suite.

import assert from "node:assert/strict";
import test from "node:test";
import { formatDeviceUserCode, isValidDeviceUserCode, normalizeDeviceUserCode } from "../../lib/device-code.ts";

test("empty device code fails format validation", () => {
  // Empty code normalizes to empty string with length 0, which fails the 8-char check
  assert.equal(normalizeDeviceUserCode(""), "");
  assert.equal(formatDeviceUserCode(""), "");
  assert.equal(isValidDeviceUserCode(""), false);

  // The component's handleSubmit calls isValidDeviceUserCode(code) as its first gate.
  // When code is "" (the initial state or after clearing), isValidDeviceUserCode returns
  // false and setError is called immediately — no session check, no network request.
  // This is verified in the companion .cjs test via rendered component interaction.
  const code = "";
  assert.equal(isValidDeviceUserCode(code), false, "empty code must fail validation");
});
