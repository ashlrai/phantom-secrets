### Added (Unix installer PATH-update tests)

- New `installer-path-tz-export` coverage pins an unrelated `export TZ`
  line surviving the installer PATH update byte-for-byte — plain, quoted,
  odd-spaced, dollar-referencing, POSIX rule, colon-prefixed zone path,
  PATH-mentioning, and marker-lookalike values; every supported final-line
  ending; a sole-line startup file; beside commented-out, TZDIR, and
  bare-assignment lookalike lines; before and after an already-wired block —
  across the bash, zsh, and fish startup files of both installer copies and
  the full offline install, and proves the preserved line still evaluates
  when the updated `.bashrc` is sourced. A node-free
  `installer-path-tz.test.sh` leg checks the same preservation in
  `apps/web/public/install.sh` with the shipped `add_to_user_path` alone.
