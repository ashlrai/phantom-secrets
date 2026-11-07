### Added (Unix installer PATH-update tests)

- New `installer-path-lc-all-export` coverage pins an unrelated `export
  LC_ALL` line surviving the installer PATH update byte-for-byte — plain,
  quoted, odd-spaced, dollar-referencing, PATH-mentioning, and
  marker-lookalike values; every supported final-line ending; a sole-line
  startup file; before and after an already-wired block — across the bash,
  zsh, and fish startup files of both installer copies and the full offline
  install, and proves the preserved line still evaluates when the updated
  `.bashrc` is sourced.
