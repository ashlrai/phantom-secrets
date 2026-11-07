import { execFileSync } from "node:child_process";

export function unmerged(dir, runGit = execFileSync) {
  const output = runGit("git", ["ls-files", "-u"], { cwd: dir, encoding: "utf8" });
  // Preserve UTF-16 code-unit order rather than locale-dependent collation.
  return [...new Set(output.trim().split("\n")
    .filter(Boolean).map((line) => line.split("\t")[1]))]
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
