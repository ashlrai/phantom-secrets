### Fixed (Unix installer PATH update)

- `install.sh` now recognizes its `# phantom-secrets PATH` marker only as a
  whole line, so an unrelated export or comment that merely mentions the
  marker text no longer suppresses the PATH update with a misleading
  "already wired" report.
