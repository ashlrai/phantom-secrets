import { execFileSync } from "node:child_process";

/** Git content history, never the build clock or a hand-maintained review date. */
export function gitLastModified(directory: string, files: readonly string[]): string | undefined {
  if (!files.length) return undefined;
  // Strip GIT_* variables (caller overrides) while preserving ProcessEnv shape
  // so Node 22's strict `env` overload accepts it.
  const safeEnv = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")),
  ) as NodeJS.ProcessEnv;
  function git(args: string[]) {
    return execFileSync("git", ["--literal-pathspecs", "-c", "core.fsmonitor=false", ...args], {
      cwd: directory,
      env: safeEnv,
      encoding: "utf8",
      timeout: 5_000,
      maxBuffer: 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  }
  try {
    // A shallow boundary looks like a root commit to `log -- path`, which can
    // falsely date unchanged files. Prefer no lastmod to a fabricated date.
    if (git(["rev-parse", "--is-shallow-repository"]) === "true") return undefined;
    // Untracked content has no publication date yet. Copied builds without Git
    // and shallow clones without relevant history omit this optional field.
    git(["ls-files", "--error-unmatch", "--", ...files]);
    const modified = git(["log", "-1", "--format=%cI", "--", ...files]);
    return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/.test(modified)
      && Number.isFinite(Date.parse(modified)) ? modified : undefined;
  } catch {
    return undefined;
  }
}
