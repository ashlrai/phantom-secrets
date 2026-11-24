// Run affected nextest and publish only the first failing test.
// The step log stays short: the full nextest transcript is not echoed.
import { spawnSync } from "node:child_process";
import { appendFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function firstFailure(text) {
    const panic = text.match(/panicked at ([^\s:]+):(\d+)/);
    const rustc = text.match(/--> ([^\s:]+):(\d+):\d+/);
    const named = text.match(/test (\S+) \.\.\. FAILED/) || text.match(/FAIL \[.*?\] \S+ (\S+)/);
    const loc = panic || rustc;
    return {
        file: loc ? loc[1].replace(/\\/g, "/") : "",
        line: loc ? loc[2] : "",
        name: named ? named[1] : "affected test failed",
    };
}

export function summarize(text, status) {
    if (status === 0) return { ok: true, markdown: "Affected tests passed.\n" };
    const hit = firstFailure(text);
    const where = hit.file ? `${hit.file}:${hit.line || "1"}` : "unknown location";
    return {
        ok: false,
        file: hit.file,
        line: hit.line || "1",
        name: hit.name,
        markdown: `Affected tests failed.\n\nFirst failure: \`${hit.name}\` at \`${where}\`.\n`,
    };
}

function run(filter) {
    const result = spawnSync(
        "cargo",
        ["nextest", "run", "--workspace", "--all-targets", "--locked", "--max-fail", "1", "-E", filter],
        { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 },
    );
    const text = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    const summary = summarize(text, result.status ?? 1);
    if (process.env.GITHUB_STEP_SUMMARY) {
        appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary.markdown);
    } else {
        process.stdout.write(summary.markdown);
    }
    if (!summary.ok) {
        const file = summary.file ? ` file=${summary.file}` : "";
        const line = summary.line ? `,line=${summary.line}` : "";
        process.stdout.write(`::error${file}${line}::${summary.name}\n`);
        process.exit(result.status || 1);
    }
}

const invoked = process.argv[1]
    && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
if (invoked) {
    const filter = process.argv[2];
    if (!filter) {
        process.stderr.write("nextest-summary: missing filterset\n");
        process.exit(2);
    }
    if (filter === "none()") {
        const note = "No affected crates.\n";
        if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, note);
        else process.stdout.write(note);
        process.exit(0);
    }
    run(filter);
}
