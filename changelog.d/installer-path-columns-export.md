### Added (Unix installer PATH-update tests)

- New `installer-path-columns-export` coverage pins an unrelated `export
  COLUMNS` line surviving the installer PATH update byte-for-byte — plain,
  quoted, odd-spaced, dollar-referencing, PATH-mentioning, and
  marker-lookalike values; every supported final-line ending; beside
  commented-out, sibling `LINES`, and bare-assignment lookalike lines; a
  sole-line startup file; before and after an already-wired block — across
  the bash, zsh, and fish startup files of both installer copies and the
  full offline install, and proves the preserved line still evaluates when
  the updated `.bashrc` is sourced. A node-free
  `installer-path-columns.test.sh` leg checks the same preservation in
  `apps/web/public/install.sh` with the shipped `add_to_user_path` alone.
  The previously orphaned `installer-path-lines-export.test.mjs` is also
  wired into the CI installer-test step so it actually runs.
