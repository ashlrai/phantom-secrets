### Changed (README get-started is five steps and drift-tested)

- The README quick start is now five numbered steps (install, protect `.env`,
  check, connect an AI client, run through the proxy) and says plainly that
  step 5 runs your own app, so what it logs is up to that app. It no longer
  recommends the Homebrew formula, which still serves v0.7.9.
- New `doc_facts` tests in `phantom-cli` fail when the README or agent docs
  drift from the code: MCP tool count, tool names and parameters, the command
  reference, `phantom import` sources, `phantom setup --client` values, and
  completion shells. They read local files only and spawn no binary.

### Fixed (headless output regression coverage)

- New tests pin that an unknown command exits `2` with a one-line suggestion
  and no interactive prompt, and that `phantom exec` keeps child stdout and
  stderr on separate streams.
