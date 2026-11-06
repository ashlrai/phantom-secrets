### Added (Unix installer PATH-update tests)

- New `installer-path-shell-export` coverage pins an unrelated `export SHELL`
  line surviving the installer PATH update byte-for-byte (same offset, exactly
  one occurrence, only the marker block appended) for bash, zsh, and fish
  startup files in both installer copies, including a line naming a different
  shell than the one in the environment and a marker-lookalike value.
