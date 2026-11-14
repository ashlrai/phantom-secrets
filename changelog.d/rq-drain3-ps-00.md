### Changed (distribution docs checks)

- The root `llms.txt` agent entry point is now a checked distribution
  guide, so its local links, anchors, and release claims are verified with
  the rest of the reader docs.

### Fixed (Unix installer test scripts)

- `scripts/installer-path-shell.test.sh` carries the executable bit like
  every sibling `.test.sh` script.
