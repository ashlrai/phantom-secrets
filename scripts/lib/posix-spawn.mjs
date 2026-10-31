import { spawnSync } from "node:child_process";

export function spawnPosixSync(command, args, options, platform = process.platform, run = spawnSync) {
  // POSIX uses a fixed launcher; Windows resolves the executable by name.
  return platform === "win32"
    ? run(command, args, options)
    : run("/usr/bin/env", [command, ...args], options);
}
