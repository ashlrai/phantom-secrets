import assert from "node:assert/strict";
import test from "node:test";

import { ALL_OSES, classifyFiles, parseCron, rustCfgLegs } from "./daily-matrix.mjs";

const values = (set) => [...set];

test("cron fields retain wildcard, singleton, range, list and step behavior", () => {
    for (const [field, expected] of [
        ["*", Array.from({ length: 60 }, (_, i) => i)],
        ["7", [7]],
        ["7-10", [7, 8, 9, 10]],
        ["7,10", [7, 10]],
        ["7-13/3", [7, 10, 13]],
        ["*/20", [0, 20, 40]],
    ]) {
        const result = parseCron(`${field} 4 * * *`);
        assert.deepEqual(values(result.minute), expected, field);
        assert.deepEqual(values(result.hour), [4], field);
    }
});

test("cron rejects malformed and out-of-range fields", () => {
    for (const field of ["", "1-", "1-2-3", "1//2", "*/0", "60", "10-7", "-1", "1,"]) {
        assert.throws(() => parseCron(`${field} 4 * * *`), undefined, field);
    }
});

test("cfg negation and quoted non-OS payloads preserve conservative coverage", () => {
    assert.deepEqual(values(rustCfgLegs('#[cfg(not(target_os = "windows"))]')),
        ["macos-latest", "ubuntu-latest"]);
    assert.deepEqual(values(rustCfgLegs('#[cfg(feature = "windows")]')), []);
    for (const expr of ["not(all(unix, test))", "not(not(windows))"]) {
        assert.deepEqual(values(rustCfgLegs(`#[cfg(${expr})]`)), ALL_OSES, expr);
    }
});

test("classification sorts reasons without changing matrix order or input", () => {
    const files = ["z.js", "a.js", "z.js"];
    const plan = classifyFiles(files, () => null);
    assert.deepEqual(plan, {
        os: ["ubuntu-latest"],
        reasons: { "ubuntu-latest": ["default: a.js", "default: z.js"] },
    });
    assert.deepEqual(files, ["z.js", "a.js", "z.js"]);
});
