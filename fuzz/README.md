# Placeholder and request-injection fuzzing

This independent Cargo workspace instruments the real `phantom-core` and
`phantom-proxy` crates without adding fuzz dependencies to release builds.
Only synthetic mappings and values are used. No vault, credentials, provider,
HTTP listener, or external service is needed. Dependencies are fetched with
`--locked`; cargo-fuzz then runs offline and the receipt verifies that the
checked-in lockfile remained byte-identical (cargo-fuzz has no `--locked` flag).

Prerequisites: macOS or Linux, Python 3, an installed Rust nightly, and
`cargo-fuzz` on PATH:

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
python3 fuzz/run.py
```

The runner builds with explicit AddressSanitizer, debug assertions,
and overflow checks, then runs **both targets concurrently for 600 seconds
each** (about ten minutes after compilation). `--toolchain nightly-YYYY-MM-DD`
selects an already installed nightly; `--seconds 5` is a smoke run and does
**not** satisfy ten-minute acceptance. The runner never installs tools.
Dependency fetching and compilation each have a separate 30-minute timeout,
configurable with `--build-timeout`; neither contributes to fuzzing duration.
Command timeouts terminate the entire process group, including
Cargo/compiler/fuzzer descendants, and reap the wrapper. Concurrent workers
remain bounded by their own timeouts if the runner is interrupted.

Each run gets a temporary HOME while preserving the actual `CARGO_HOME` and
`RUSTUP_HOME`. Logs and a JSON receipt are retained under `fuzz/logs/<UTC>/`.
A target passes only after a zero exit, the full requested duration reported
by libFuzzer itself, matching nonzero completion/statistics execution counts,
and no crash/timeout/OOM artifacts. Build failures
also produce a failing receipt. Inputs are bounded to 16 KiB, single executions
to ten seconds, and each process to a 2 GiB libFuzzer RSS limit. These are
resource bounds, not substitutes for the production proxy body-size tests.

The checked-in `logs/acceptance-*` receipt and raw final-stat logs record the
task's ten-minute run. Other generated logs, corpora, artifacts and build files
are ignored. Checked-in `seeds/` are immutable synthetic regression inputs;
the runner copies them into mutable `corpus/` before every run. Retain any
interesting minimized failure as a new synthetic seed after investigating it.

## Properties

- `placeholder_parsing`: the prefix-only parser and predicate agree with an
  independent byte-prefix oracle, preserve accepted text exactly, and round
  trip. Exercises arbitrary UTF-8, invalid bytes via lossy decoding, NULs,
  truncation, Unicode, and prefixed/unprefixed variants. Acceptance of short or
  non-hex `phm_` strings is the existing compatibility contract.
- `body_injection`: arbitrary bytes and valid JSON, form, and multipart bodies
  containing known synthetic mappings remain byte-identical through every
  client substitution API. Six independent control bytes select behavior
  without corrupting the remaining raw payload. Varies
  MIME types, all three interceptor constructors, matching/missing/arbitrary
  route names, streaming carry, empty frames and chunk boundaries. Neither
  token inspection nor client-header formatting authorizes resolution. A
  configured named route can still format its own authentication header.

The body compatibility functions are deprecated and intentionally inert. The
live HTTP server forwards its bounded body directly, rather than calling those
helpers. These targets guard the substitution boundary; existing proxy server
integration tests separately cover actual HTTP forwarding. This campaign does
not establish exhaustive coverage or live-provider acceptance.

## Regression checks

Use a temporary HOME for tests; keep the toolchain directories explicit:

```sh
TASK_TEST_HOME=$(mktemp -d)
TASK_CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
TASK_RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}
HOME="$TASK_TEST_HOME" CARGO_HOME="$TASK_CARGO_HOME" RUSTUP_HOME="$TASK_RUSTUP_HOME" \
  cargo test --manifest-path fuzz/Cargo.toml --locked --lib --test regression
HOME="$TASK_TEST_HOME" python3 -m unittest discover -s fuzz -p 'test_*.py' -v
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings
```

The deterministic Rust tests replay prefix/binary/large-input boundaries and
4,347 constructor/MIME/route/chunk combinations plus 483 mapping carry splits.
Python tests verify that early
exit, missing execution statistics, crashes, launch errors, and timeouts cannot
produce a passing receipt. To reproduce a discovered input directly:

```sh
cargo +nightly fuzz run --fuzz-dir fuzz body_injection fuzz/artifacts/<run>/body_injection/<input>
```
