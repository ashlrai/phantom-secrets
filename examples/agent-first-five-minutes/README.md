# First five minutes with an installed Phantom runtime

Check the actual CLI and MCP transport before connecting your coding client.
This companion to the [static delegation contract](../first-five-minutes/README.md)
uses a disposable empty workspace and home directory. It supplies no credentials,
does not initialize a vault, and calls no provider API.

## Run

Prerequisites: Node.js 22 or newer and reviewed, matching `phantom` and
`phantom-mcp` binaries for your current macOS, Windows, or Linux machine. Install
them using [getting started](../../docs/getting-started.md#install).

From the repository root:

```text
node examples/agent-first-five-minutes/run.mjs
```

The example finds binaries on PATH. To select binaries explicitly, supply
absolute paths, with quotes around paths containing spaces:

```text
node examples/agent-first-five-minutes/run.mjs --phantom /absolute/path/phantom --mcp /absolute/path/phantom-mcp
```

On Windows, use absolute Windows paths and the `.exe` filenames. The Node
script uses subprocess argument arrays, so it does not require Bash.

## Read the result

Each `PASS` comes from an executed check:

- CLI and standalone MCP version responses, with matching versions;
- CLI `status --oneline` recognizing an uninitialized workspace;
- both `phantom mcp serve` and `phantom-mcp` completing MCP initialization,
  returning a unique tool catalog, and answering `phantom_status` and
  `phantom_capability`;
- the capability card reporting no active Locus seal and explicit boundaries
  for secret revelation and engineering execution; and
- the temporary workspace and home remaining empty after the read-only calls.

Exit `0` means all checks passed. Exit `2` means an executable prerequisite was
missing; `SKIP` is incomplete evidence. Exit `1` means a check failed. Commands
time out after ten seconds; MCP processes are stopped and the disposable
directory is removed when the script finishes. The script withholds raw child
diagnostics rather than printing arbitrary configuration or response contents.

The script passes only operating-system launch variables and its temporary
paths to child processes. It deliberately avoids `agent report`, whose normal
cloud-login probe can read the OS keychain even with a temporary HOME. This
example is not an OS sandbox; run only binaries you have verified.

No output here proves credential protection, proxy injection, client UI
activation, provider acceptance, or deployment. Those checks appear explicitly
as `NOT TESTED`. Continue with the [delegation quickstart](../../docs/delegation-quickstart.md)
for your real project, and restart the selected client after MCP setup.

## Test the smoke harness

```text
node --test scripts/agent-first-five-minutes.test.mjs
```

Regression tests check missing prerequisites, unexpected version output,
malformed protocol data, a hung server, and version mismatch. Script-based fake
runtime tests run on Unix; Windows reports those fixtures as skipped. These
fixtures test the harness, while the command above with installed binaries
tests Phantom itself on the current machine.
