import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

test("CodeQL scans PRs and main without merge queue runs", () => {
    const workflow = readFileSync(new URL("../.github/workflows/codeql.yml", import.meta.url), "utf8");
    const triggers = workflow.match(/^on:\n([\s\S]*?)(?=^\S)/m)?.[1];
    assert.ok(triggers, "workflow trigger block exists");
    const events = [...triggers.matchAll(/^  ([a-z_]+):/gm)].map((match) => match[1]);
    assert.deepEqual(events, ["push", "pull_request", "schedule", "workflow_dispatch"]);
    assert.match(triggers, /^    branches: \[main\]$/m);
    assert.match(triggers, /^    types: \[opened, synchronize, reopened, ready_for_review\]$/m);
    assert.equal([...triggers.matchAll(/^    - cron:/gm)].length, 2);
});
