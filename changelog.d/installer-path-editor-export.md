### Added (Unix installer PATH-update tests)

- New `installer-path-editor-export` coverage pins an unrelated `export
  EDITOR` line surviving the installer PATH update byte-for-byte — plain,
  quoted, PATH-lookalike, and marker-lookalike values; every supported
  final-line ending; a sole-line startup file; before and after an
  already-wired block — across the bash, zsh, and fish startup files of both
  installer copies and the full offline install, and proves the preserved
  line still evaluates when the updated `.bashrc` is sourced.

### Fixed (Unix installer PATH-update tests)

- `installer-path-trailing-newline` no longer expects the pre-0.8.1
  substring marker check: a startup file that merely mentions the
  `# phantom-secrets PATH` text is now wired like any unmarked file and its
  mentioning line preserved, matching the line-exact `grep -qxF` contract.
