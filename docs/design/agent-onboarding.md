# Agent onboarding: one entry point with a dry-run diff

Status: design note. Docs only. Nothing here changes code.

Facts were checked on 2026-10-18 against phantom-secrets `main` at `34513e2`, phantom `master` at `332af868`, and ashlr-stack `main`. Claims about behavior come from reading the code, not from running every client.

## 1. Current state (three surfaces, one job)

| Surface | Command | Clients | Dry run | Backup | Undo | Differing entry |
|---------|---------|---------|---------|--------|------|-----------------|
| phantom-secrets (Rust) | `phantom setup --client <c>` | Claude Code, Cursor, Windsurf, Codex, Gemini CLI | no (`--print` shows a snippet only) | no | yes for Cursor, Windsurf, Gemini CLI, Codex (slice 2) | no | refused unless `--replace` (slice 2) |
| phantom-secrets (Rust) | `phantom setup --status` | same five | read-only report | n/a | n/a | n/a |
| phantom (TS) | `phm wire <c>` and `wire status` | Claude Code, Codex, Cursor write; Gemini and Windsurf status only | no | no | no | not verified here |
| phantom (TS), PR #821 (draft) | `phm wire sync [--apply\|--undo]` | JSON clients from the client table (Codex skipped) | yes, default | yes, plus manifest | yes, hash checked | `conflict`, exit 1, never overwritten |
| ashlr-stack (merged #52) | `stack onboard [--apply\|--undo]` | Claude Code, Codex, Cursor, Gemini CLI | yes, default | yes | yes | plan reports it, not written |
| phantom TS, PR #813 (draft) | `phm wire table` | client table JSON | read-only | n/a | n/a | n/a |

Server names differ by surface: the TS side registers `ashlr-hub`, the Rust side registers `phantom`. phantom-secrets has a contract test that vendors the client table (`crates/phantom-cli/tests/fixtures/client-table.json`) for ids, labels, paths and formats.

Gap: the Rust `phantom setup --client` is the entry point most users hit first, and it is the only one with no preview, no backup, no undo, and a silent overwrite of a differing `phantom` entry. The TS `wire sync` (#821) and `stack onboard` already have the safe shape. This note defines that shape once so the Rust command can adopt it.

## 2. Single entry point

Keep `phantom setup` as the one user-facing command in phantom-secrets. Do not add a new top-level command. Targets:

- `phantom setup` with no client: plan for every detected client (dry run, writes nothing).
- `phantom setup --client <c>`: plan for one client, even if not detected.
- `--apply`: write.
- `--undo`: restore the last applied set.
- `--status`: unchanged, read-only.
- `--print`: unchanged.

Compatibility: today `phantom setup --client codex` writes immediately. Flipping that to a dry run is a visible behavior change, so it ships in two steps: first an opt-in `--dry-run` (no behavior change), then, after a release note, the default flips and `--apply` is required. The flip is Mason's call (it changes documented commands in claude-code.md, codex.md, cursor.md).

## 3. Detection

A client is detected when its config directory exists under the home directory or its binary is on PATH. Detection only reads metadata; it never runs the vendor CLI. Paths (from the Rust writer today):

| Client | Config file | Format |
|--------|-------------|--------|
| Cursor | `~/.cursor/mcp.json` | JSON, `mcpServers` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | JSON, `mcpServers` |
| Gemini CLI | `~/.gemini/settings.json` | JSON, `mcpServers` |
| Codex | `~/.codex/config.toml` | TOML, `mcp_servers` |
| Claude Code | project `.mcp.json` plus project settings plan | JSON, with a separate approval step |

Windows paths are not independently verified.

## 4. Dry-run diff

The plan lists one row per client with an action:

- `add`: no entry named `phantom`; the diff shows the added lines only.
- `unchanged`: the entry already equals the expected one.
- `conflict`: an entry named `phantom` exists and differs. Shown as a before and after diff. Never written without an explicit flag (section 5).
- `invalid`: the file is not parseable or not the expected shape. Never touched, byte for byte.
- `skip`: not detected, and no explicit target.

The diff prints the command path and args only. It never prints environment values or any other key in the file (other keys can hold secrets), so unrelated keys are shown as "N other keys preserved" without values. `--json` output carries the same rows.

## 5. Write rules

1. Re-read the file immediately before writing and refuse if it changed since the plan (the existing safe-publish path in `setup.rs` already compares before replacing).
2. Existing unsafe-path protections stay: no symlinked parents, ownership checks, private permissions on new files.
3. A `conflict` row is not written by `--apply`. A separate `--replace` flag (one client at a time) opts in, and it still takes a backup first.
4. Backup before every write to an existing file: `<config>.phantom-bak-<ms>` copied byte for byte, mode preserved. A manifest records every file touched, the backup path, the SHA-256 of the written bytes, and whether the file was newly created.
5. Unrelated keys, comments in TOML, and ordering are preserved. Where the JSON or TOML writer cannot preserve something, the row is `invalid` rather than lossy.

## 6. Undo

`--undo` reads the manifest, and for each file: if the file's SHA-256 still matches what setup wrote, restore from the backup (or delete the file if setup created it); otherwise refuse that file and keep the backup. A refused file never blocks the others. Undo never touches files outside the manifest.

## 7. What stays manual

- Restarting the client after a change.
- Approving the MCP server inside Claude Code (project `.mcp.json` requires approval there).
- Cursor and Gemini in-app toggles for MCP servers.
- Any client-managed registry (for example a client's own `mcp add` command): setup does not call vendor CLIs.
- Project-level config files in repos the user has not enrolled.
- Provider API keys: never read, written or printed by onboarding.

## 8. Proposed slices (small PRs, one at a time per repo)

1. phantom-secrets: `phantom setup --client <c> --dry-run` for the JSON clients and Codex, planning only, no behavior change. Tests: plan matches what a real write produces; nothing written; invalid file untouched.
2. phantom-secrets: backup plus manifest before an existing-file write (no output change except one line naming the backup).
3. phantom-secrets: `phantom setup --undo` (done: dry run by default, `--undo --apply` performs it, `--force-undo` overrides only the hash check).
4. phantom-secrets: `conflict` refusal and `--replace` (behavior change, needs release note; Mason decision).
5. phantom-secrets: `phantom setup` with no client plans all detected clients.
6. Cross-repo: keep the vendored client-table fixture current when phantom #813 merges.
7. phantom: land #809 chain (#813, #821) when Mason reviews; stack `onboard` is already merged.

Open questions for the owner: should the default flip to dry run (section 2), and should the Rust and TS surfaces converge on one server name?
