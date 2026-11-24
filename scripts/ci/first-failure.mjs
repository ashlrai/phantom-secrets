// Publish only the first compiler or test failure. The workflow runs cargo.
// This file does not spawn a process.
import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function firstFailure(text) {
    const panic = text.match(/panicked at ([^\s:]+):(\d+)/);
    const rustc = text.match(/--> ([^\s:]+):(\d+):\d+/);
    const named = text.match(/test (\S+) \.\.\. FAILED/) || text.match(/FAIL \[.*?\] \S+ (\S+)/);
    const loc = panic || rustc;
    const lead = text
        .split("\n")
        .map((line) => line.trim())
        .find((line) => line.length > 0) || "";
    return {
        file: loc ? loc[1].replace(/\\/g, "/") : "",
        line: loc ? loc[2] : "",
        name: named ? named[1] : "build failed",
        lead: lead.slice(0, 180),
    };
}

export function summarize(text, status) {
    if (status === 0) return { ok: true, markdown: "Build and tests passed.\n" };
    const hit = firstFailure(text);
    const where = hit.file ? `${hit.file}:${hit.line || "1"}` : "unknown location";
    const hint = !hit.file && hit.lead ? `\n\`${hit.lead}\`\n` : "";
    return {
        ok: false,
        file: hit.file,
        line: hit.file ? (hit.line || "1") : "",
        name: hit.name,
        markdown: `Build or tests failed.\n\nFirst failure: \`${hit.name}\` at \`${where}\`.\n${hint}`,
    };
}

export function annotation(summary) {
    if (summary.ok) return "";
    const file = summary.file ? ` file=${summary.file}` : "";
    const line = summary.file && summary.line ? `,line=${summary.line}` : "";
    return `::error${file}${line}::${summary.name}`;
}

function publish(summary) {
    if (process.env.GITHUB_STEP_SUMMARY) {
        appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary.markdown);
    } else {
        process.stdout.write(summary.markdown);
    }
    if (!summary.ok) {
        process.stdout.write(`${annotation(summary)}\n`);
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
        process.stderr.write("first-failure: need --status <exit> --log <file>\n");
        process.exit(2);
    }
    publish(summarize(readFileSync(logPath, "utf8"), Number(statusText)));
}
