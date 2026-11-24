// OS gate: pass when every needed job succeeded or was skipped by a path
// gate. Fail on failure or cancellation. Does not spawn a process.
import { appendFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function decide(needs) {
    const bad = [];
    for (const [name, job] of Object.entries(needs)) {
        const result = job?.result;
        if (result !== "success" && result !== "skipped") bad.push(`${name}=${result ?? "missing"}`);
    }
    return { ok: bad.length === 0, bad };
}

function publish(result) {
    const markdown = result.ok
        ? "OS gate passed.\n"
        : `OS gate failed.\n\n${result.bad.join("\n")}\n`;
    if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
    else process.stdout.write(markdown);
    if (!result.ok) {
        process.stdout.write(`::error::${result.bad.join(", ")}\n`);
        process.exit(1);
    }
}

const invoked = process.argv[1]
    && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
if (invoked) {
    const needs = JSON.parse(process.env.NEEDS || "{}");
    publish(decide(needs));
}
