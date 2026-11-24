### CI (Linux, Windows, and macOS gates)

- Pull requests and the merge queue report `Gate (linux)`, `Gate (windows)`,
  and `Gate (macos)`. Windows and macOS build and test only when the platform
  path gate selects them. Each gate passes when its jobs succeed or that gate
  skips them.
- `install smoke (linux)`, `install smoke (windows)`, and `install smoke (macos)`
  install the CLI and run `phantom --help`, `phantom init`, and
  `phantom init --empty`. The daily run also checks the latest published
  release archive. These jobs are not part of `CI Gate`.
