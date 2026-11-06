### Added (Unix installer PATH-update tests)

- New `installer-path-alias-fallback` coverage pins an unrelated shell alias
  surviving the installer PATH update byte-for-byte across the startup-file
  fallbacks: unset `SHELL` (the installer runs under bash, which assigns the
  login shell at startup — the update lands in that shell's startup file),
  empty `SHELL` (the `${SHELL:-bash}` default → `.bashrc`), unrecognized
  shells (`sh`, `dash`, `tcsh` → `.bashrc`), and pathless names (`zsh`,
  `fish`) that `basename` maps to their own startup files — each routed to
  the file the installer actually chooses, with every other shell's startup
  file left byte-for-byte untouched, in both installer copies. A marker-only
  file (marker line present, PATH line absent) is already wired for
  `grep -qxF`, so its alias stays untouched, and a full offline install with
  `SHELL` unset proves the login-shell wiring end to end. A node-free
  `installer-path-alias-fallback.test.sh` leg checks the same fallbacks in
  `apps/web/public/install.sh` with the shipped `add_to_user_path` alone.
  Both legs are wired into CI.
