### Added (Unix installer PATH-update tests)

- New `installer-path-lang-export` coverage pins an unrelated `export LANG`
  line surviving the installer PATH update byte-for-byte — plain, quoted,
  odd-spaced, dollar-referencing, PATH-mentioning, and marker-lookalike
  values; every supported final-line ending; a sole-line startup file;
  inside a realistic LC_ALL/LANGUAGE/LC_CTYPE locale block; before and after
  an already-wired block — across the bash, zsh, and fish startup files of
  both installer copies and the full offline install, and proves the
  preserved line still evaluates when the updated `.bashrc` is sourced. A
  node-free `installer-path-lang.test.sh` leg checks the same preservation
  in `apps/web/public/install.sh` with the shipped `add_to_user_path` alone.
