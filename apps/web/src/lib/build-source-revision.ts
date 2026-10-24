import { execFileSync } from "node:child_process";

const GIT_OBJECT_PATTERN = /^[0-9a-f]{40}$/;

// This is a build observation, not a platform Git association or an attestation.
// Ignore caller Git overrides so a build cannot silently inspect another repo.
export function readBuildSourceRevision(directory: string): string | null {
  const gitEnvironment = { ...process.env };
  for (const name of Object.keys(gitEnvironment)) {
    if (name.startsWith("GIT_")) delete gitEnvironment[name];
  }
  function git(...args: string[]): string {
    return execFileSync(
      "git",
      ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", ...args],
      {
        cwd: directory,
        env: gitEnvironment,
        encoding: "utf8",
        timeout: 5_000,
        maxBuffer: 1024 * 1024,
        stdio: ["ignore", "pipe", "ignore"],
      },
    ).trim();
  }
  function hiddenIndexEntries(): boolean {
    return git("ls-files", "-v", "-z")
      .split("\0")
      .some((entry) => entry !== "" && !entry.startsWith("H "));
  }
  try {
    const revision = git("rev-parse", "--verify", "HEAD^{commit}");
    const tree = git("rev-parse", "--verify", "HEAD^{tree}");
    if (!GIT_OBJECT_PATTERN.test(revision) || !GIT_OBJECT_PATTERN.test(tree)) {
      return null;
    }
    // Both staged/unstaged changes and untracked source make HEAD insufficient.
    // Status hides assume-unchanged/skip-worktree entries. Refuse those flags
    // before relying on a clean status to describe the bytes being compiled.
    if (hiddenIndexEntries() || git("status", "--porcelain=v1", "--untracked-files=all")) {
      return null;
    }
    // Catch source drift during observation; publication still checks the exact
    // clean source again after compiling and admits its matching CI separately.
    if (
      git("rev-parse", "--verify", "HEAD^{commit}") !== revision ||
      git("rev-parse", "--verify", "HEAD^{tree}") !== tree ||
      hiddenIndexEntries() ||
      git("status", "--porcelain=v1", "--untracked-files=all")
    ) {
      return null;
    }
    return revision;
  } catch {
    // Copied/unversioned or dirty builds can run locally, but cannot be ready.
    return null;
  }
}
