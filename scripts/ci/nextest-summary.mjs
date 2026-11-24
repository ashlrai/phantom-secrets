// Publish only the first failing test from a nextest log.
// The workflow runs cargo. This file does not spawn a process.
import { appendFileSync, readFileSync, realpathSync } from "node:fs";
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

function publish(summary) {
    if (process.env.GITHUB_STEP_SUMMARY) {
        appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary.markdown);
    } else {
        process.stdout.write(summary.markdown);
    }
    if (!summary.ok) {
        const file = summary.file ? ` file=${summary.file}` : "";
        const line = summary.line ? `,line=${summary.line}` : "";
        process.stdout.write(`::error${file}${line}::${summary.name}\n`);
        process.exit(1);
    }
}

function arg(name) {
    const index = process.argv.indexOf(name);
    return index === -1 ? "" : (process.argv[index + 1] ?? "");
}

const invoked = process.argv[1]
    && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
if (invoked) {
    const statusText = arg("--status");
    const logPath = arg("--log");
    if (!/^(0|[1-9][0-9]{0,2})$/.test(statusText) || !logPath) {
        process.stderr.write("nextest-summary: need --status <exit> --log <file>\n");
        process.exit(2);
    }
    const text = readFileSync(logPath, "utf8");
    publish(summarize(text, Number(statusText)));
}
