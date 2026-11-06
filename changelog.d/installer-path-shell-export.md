### Added (Unix installer PATH-update tests)

- New `installer-path-shell-export` coverage pins an unrelated `export
  SHELL` line surviving the installer PATH update byte-for-byte — plain,
  quoted, odd-spaced, dollar- and command-referencing, PATH-mentioning, and
  marker-lookalike values; every supported final-line ending; a sole-line
  startup file; beside commented-out, `SHELL_SESSION_HISTORY`, and
  bare-assignment lookalike lines; before and after an already-wired block —
  across the bash, zsh, and fish startup files of both installer copies and
  the full offline install, proves a SHELL claim inside a file cannot
  redirect the update away from the env-selected startup file, and proves
  the preserved line still evaluates when the updated `.bashrc` is sourced.
  A node-free `installer-path-shell.test.sh` leg checks the same
  preservation in `apps/web/public/install.sh` with the shipped
  `add_to_user_path` alone.
