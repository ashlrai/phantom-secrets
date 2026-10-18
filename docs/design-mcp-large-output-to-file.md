# Design note: large MCP tool outputs as "file path plus summary"

Status: proposal only. Nothing in this note is implemented. Line numbers refer to `origin/main` at 5381703.

## Problem

An MCP response lands in the agent's context window. Several `phantom-mcp` tools can return very large bodies, and every `report_result` response carries the data twice: once as a pretty-printed JSON text block and once as `structuredContent`.

Where responses are produced today:

- `crates/phantom-mcp/src/tools/helpers.rs:207` `text_result`, `:216` `report_result` (summary text, pretty JSON text, and `structured_content`), `:235` `json_object_result` (pretty JSON plus `structured_content`).
- `crates/phantom-mcp/src/server.rs:5703` `MCP_ANALYTICS_MAX_BYTES` (1 MiB) and `:5685` `MCP_ANALYTICS_MAX_RECORDS` (10,000). The comment above the byte limit says the CLI may write 64 MiB to a file while an MCP response gets a much smaller ceiling.
- `server.rs:5707` `shrink_to_fit`, `:5750` `bounded_compliance_report`, `:5967` `bounded_lists_result`: today the only strategy for large output is to drop records and report `records_truncated`. The dropped records are simply unavailable to the agent.
- Largest producers: `phantom_audit_analytics` (`:3865`), `phantom_audit_export_report` (`:4265`), plus the report tools `phantom_doctor` (`:1955`) and `phantom_check` (`:2631`).

Truncation loses data, and 1 MiB of JSON is still large for a context window. A file path plus a short summary lets the agent read only the slice it needs.

## Proposal

Add one helper in `tools/helpers.rs`, for example `spill_or_inline(summary, report, tool_name)`, used by the report tools above (not by small tools such as `phantom_list_secrets`).

1. Serialize the report to pretty JSON as today.
2. If the JSON is at or under the threshold, return exactly what `report_result` returns now. No behavior change for small results.
3. If it is over the threshold, write the full JSON to a file and return: the summary text, plus a small JSON object with `output_file` (absolute path), `bytes`, `sha256`, `records_total`, the exact scalar totals the tool already reports, `top_n` highlights (the same ranking the bounded builders use), and a one-line hint on how to read it. `structuredContent` carries the same small object, not the full report.

The existing `records_truncated` machinery stays as the fallback when the file cannot be written, so a failure to spill never fails the tool.

## Value-free rule

Only reports that are already value-blind are eligible. An allowlist of tool names in the helper decides eligibility (default deny for any new tool). The eligible tools must contain names, counts, timestamps and scores only, never secret values, placeholders' real counterparts, or vault material. The test below enforces this with canary values.

Tools that can touch values (anything that decrypts, exports, pulls or shows a secret) are never spilled and keep their current inline behavior.

## Threshold

Default 64 KiB of pretty JSON (about 16k tokens at 4 bytes per token, an estimate, not measured). Overridable with `PHANTOM_MCP_SPILL_BYTES`. A value of `0` means always spill, and a very large value effectively disables spilling. The threshold is checked against the serialized body, not the record count.

## File location and permissions

- Directory: `~/.phantom/mcp-output/<project_id>/`, following the existing `~/.phantom/` convention (`crates/phantom-core/src/audit.rs:1434` builds `~/.phantom/audit.log`). `project_id` comes from `PhantomConfig::project_id_from_path` as used in `server.rs:468`.
- Directory mode `0700`, file mode `0600`, created with `O_CREAT | O_EXCL` and the mode set at open time, the same pattern as `crates/phantom-cli/src/commands/export_cmd.rs:691`. Refuse to write if the directory is a symlink or not owned by the current user.
- File name: `<tool>-<UTC timestamp>-<random 8 hex>.json`. No secret names in file names.
- On Windows, rely on the per-user profile ACL and document that `0600` semantics do not apply.
- Cleanup: on each spill, delete files in that project directory older than 24 hours (override `PHANTOM_MCP_SPILL_TTL_HOURS`), and keep at most 20 files per project. A `phantom doctor` check lists the directory and size, and warns if a file is group or world readable.
- The agent can only read the file if its client has filesystem access. Clients without it need the opt-out.

## Opt-out

- `PHANTOM_MCP_SPILL=0` in the MCP server environment keeps today's inline-with-truncation behavior exactly.
- Per call: tools that already take `max_records` keep honoring it, and a new optional `inline: true` parameter forces inline output within the existing 1 MiB ceiling.
- Default for the first release: opt-in (`PHANTOM_MCP_SPILL=1`), flipped to default-on after one release if no client reports trouble. The tool descriptions would mention `output_file` so agents know to expect it.

## Tests

1. Under the threshold the response is byte-identical to today's `report_result` output (golden test).
2. Over the threshold the response contains `output_file`, the file exists, parses as JSON, equals the original report, and its `sha256` matches.
3. Unix: file mode is `0600` and directory mode is `0700`; a pre-existing symlinked directory is refused and the tool falls back to inline truncation.
4. Value-free canary test: seed the vault with a canary secret value, run every eligible tool, and assert the canary appears in neither the response nor the spilled file.
5. Cleanup test: files older than the TTL are removed and the per-project cap holds.
6. `PHANTOM_MCP_SPILL=0` and `inline: true` restore the current behavior; an unwritable directory falls back to truncation without failing the tool.
7. `scripts/release/mcp-schema-contract.mjs` still passes, since the tool input schema only gains the optional `inline` field.

## Open questions

- Should the file path be returned as a `resource_link` content block so clients can fetch it through MCP instead of the filesystem? This needs a check of what the pinned `rmcp` version supports; not verified here.
- Does any shipped client strip or ignore `structuredContent`, so that the small object must also appear in the text block? Not verified.
- Are 24 hours and 20 files the right retention? These are proposals, not measured.

## Ownership

`phantom-secrets` has no `CODEOWNERS` file on `main` (checked `CODEOWNERS`, `.github/CODEOWNERS` and `docs/CODEOWNERS` in the origin/main tree), so this docs-only PR and the later `crates/phantom-mcp/` change are not code-owned. The sibling `phantom` repo does have `.github/CODEOWNERS` (owner @masonwyatt23), but its MCP surface is not touched by this note.
