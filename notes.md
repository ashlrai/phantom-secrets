# RQ-PERF-12-PS audit notes

- tools/mod.rs only exports helpers and params. Tool-level descriptions are declared in server.rs.
- Runtime baseline ListToolsResult: 71,405 bytes for 54 tools, including resultType=complete. The tools-only registry envelope is 71,381 bytes.
- rmcp already strips root schema titles and descriptions. All validation fields, defaults, nulls, required lists, definitions and references are retained.
- A baseline snapshot retains every non-description catalog field. CLI snapshots cover absent and populated optional list metadata and complete doctor reports.
- CLI list and doctor already omit absent optional fields. Compact JSON is safer than removing consumer data; stdout still ends with one newline. Doctor file output uses the same format.
- Runtime serialization confirms a saving of 3,476 bytes (4.87%).
- Exact registry parity is enforced by scripts/release/mcp-stdio-smoke.mjs. A description-only mirror update is prepared in /tmp/rq-perf-registry-description-update.patch. The repository registry remains untouched pending clarification of the release/publish config restriction.
- Tests use temporary HOME directories with real CARGO_HOME and RUSTUP_HOME. The initial build is cold and subsequent test/check profiles compile additional feature combinations.

All 318 current Rust tests pass. Workspace check, clippy and formatting pass. Reviewed-mirror smoke passes; unchanged repository-mirror smoke fails exact prose parity.
