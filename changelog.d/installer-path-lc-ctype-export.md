### Added (Unix installer PATH-update tests)

- New `installer-path-lc-ctype-export` coverage pins an unrelated `export
  LC_CTYPE` line surviving the installer PATH update byte-for-byte — plain,
  quoted, odd-spaced, dollar-referencing, PATH-mentioning, and
  marker-lookalike values; every supported final-line ending; commented-out,
  sibling `LC_*`, and bare-assignment lookalike lines beside the export; a
  sole-line startup file; before and after an already-wired block — across
  the bash, zsh, and fish startup files of both installer copies and the
  full offline install, and proves the preserved line still evaluates when
  the updated `.bashrc` is sourced. A node-free
  `installer-path-lc-ctype.test.sh` leg checks the same preservation in
  `apps/web/public/install.sh` with the shipped `add_to_user_path` alone.
