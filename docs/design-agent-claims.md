# Design note: agent claims and status that other agent sessions can read

Status: proposal only. Nothing in this note is implemented. Written against `origin/main` of phantom-secrets.

## Problem

Several agent sessions (Claude Code, Codex, Cursor, a human) can work in one project at the same time. Today they coordinate through a hand-edited markdown board (`COORDINATION.md` in the maintainers' workspace). That works for a few agents with a human sweeping it, but it has no structure, no expiry, no locking, and it is not visible to a session that only has Phantom's MCP server. Stale claims are removed by hand.

The goal is a small, value-free record of "who is working on what" that any session can read through Phantom, with expiry and safe concurrent writes.

## Non-goals

- Not a task tracker, scheduler, chat channel or message bus between agents.
- Not a permission system. A claim does not grant or deny access to any secret, and does not replace MCP approvals or code-owner review.
- Not shared across machines in the first version. It is local to one project checkout on one machine.
- No secrets, secret names, values, placeholders, prompts, file contents or diffs. See "Value-free rule".

## How it differs from COORDINATION.md

| | COORDINATION.md | Proposed claims file |
|---|---|---|
| Format | free markdown | one JSON document with a fixed schema |
| Expiry | manual removal | every claim has `expires_at`; expired claims are ignored and pruned |
| Concurrency | last writer wins | advisory file lock plus atomic rename |
| Reader | a human or an agent that can open the file | `phantom claims` CLI and a read-only MCP tool |
| Scope | whole workspace, many repos | one project directory |
| Content | decisions, blockers, research pointers | claim id, agent label, a short free-text slice label, timestamps |

COORDINATION.md keeps its role for decisions and blockers. The claims file only answers "is this slice taken, by whom, until when".

## Proposal

### File

`~/.phantom/claims/<project_id>.json`, where `project_id` comes from `PhantomConfig::project_id_from_path` (`crates/phantom-core/src/config.rs`), the same id the MCP server already uses. This keeps the file out of the repository, so it cannot be committed by accident and needs no `.gitignore` entry. Directory mode `0700`, file mode `0600`, created with the mode set at open time, refusing a symlinked directory or file, following the pattern in `crates/phantom-core/src/mcp_approval.rs`.

### Schema (version 1)

```json
{
  "version": 1,
  "claims": [
    {
      "id": "c-<random 8 hex>",
      "agent": "claude-code",
      "slice": "doctor --all report",
      "created_at": 1760000000,
      "expires_at": 1760003600,
      "status": "active"
    }
  ]
}
```

- `agent`: a short label chosen by the caller, matched against `^[a-z0-9][a-z0-9._-]{0,31}$`. It is a label, not an identity. Nothing authenticates it.
- `slice`: free text, at most 80 characters, printable ASCII only. The tool rejects text that looks like a secret (the same shape detectors `phantom check` already uses) and rejects any text that matches a name in the project's vault, so a careless caller cannot park a secret in the board. This is a guard against accidents, not a security boundary.
- `status`: `active` or `done`. A `done` claim stays visible until it expires, so other sessions can see recent completions.
- Maximum 64 claims per file. A write that would exceed it fails with a clear error after pruning expired entries.

### Expiry

Default lifetime 1 hour, maximum 24 hours, set at claim time. A session extends a claim by calling renew with the claim id, which resets `expires_at` from now (still capped at 24 hours from `created_at`). Readers drop claims whose `expires_at` is in the past. The next write prunes them. There is no daemon: expiry is evaluated at read and write time against the system clock. Clock skew is not an issue on one machine, and the note flags it as a limit if the file is ever shared.

### Locking

Writers take an exclusive `fs2` lock on a sibling `<project_id>.lock` file (the same crate and approach `mcp_approval.rs` uses for `mcp-approvals.lock`), read the JSON, change it, write a temp file in the same directory and `rename` it over the target, then unlock. Readers take no lock: the atomic rename guarantees they see either the old or the new complete file. A reader that cannot parse the file reports it as unreadable and does not repair it.

Claiming is first come first served: claiming a `slice` string that matches an active claim by a different `agent` (case-insensitive, whitespace trimmed) fails and returns the existing claim's agent, `slice` and `expires_at`. Matching is exact on the normalized string, so near-duplicates are not detected. That is a known limit: this is cooperative, not enforced.

### Surfaces

1. **CLI (read and write).** `phantom claims list [--json]`, `phantom claims add --agent <label> --slice <text> [--ttl <minutes>]`, `phantom claims renew <id>`, `phantom claims done <id>`. All commands act on the current project. `list` never writes, not even to prune, and creates no directories (same property `agent status` has, with a test that a fresh HOME stays empty).
2. **MCP tool, read-only.** `phantom_claims_list`, returning the same JSON as `phantom claims list --json`. It has no parameters and never writes or creates anything. The MCP surface gets no write tool in the first version. Reason: MCP callers are the agents themselves, and the server's existing rule is that anything that changes state needs a human-visible step (see MCP approvals). A session that wants to claim a slice runs the CLI command, which is an ordinary shell call the user can see. If sessions need to write through MCP later, that should go through the existing approval flow and be reviewed as its own change.
3. **`phantom doctor --all`.** Could show the count of active claims later. Not part of the first slice.

### Value-free rule

The file holds only the fields in the schema. The tests (below) seed a canary secret in the vault and in the environment and assert it appears in no claims file, CLI output, MCP response, or error. The `agent` and `slice` fields are caller-supplied free text, so the note treats them as untrusted when read: an MCP client that reads a claim must treat the `slice` text as data, never as an instruction. The tool description says so, and the response wraps the field values in a JSON string, never as markdown or instructions. This matters because another session's text is an injection vector, the same way untrusted email or webhook text is.

### Why this is small and where it would live

- `crates/phantom-core`: a new `claims` module (types, validation, locked read-modify-write), modeled on `mcp_approval.rs`. About the size of that module's storage half, no new dependencies (`fs2`, `serde_json`, `sha2` are already used).
- `crates/phantom-cli`: a `claims` command module and the `Commands::Claims` variant in `main.rs`, plus the grouped `--help` list (a past PR failed a help test for a missing entry).
- `crates/phantom-mcp`: one read-only tool in `server.rs` next to the other read-only report tools (for example the doctor and check tools), with the read-only behavior covered by the same style of guard test as the Temporal MCP guard test.
- The separate `ashlrai/phantom` repository has its own fleet MCP tools in TypeScript, and many of its test paths are code-owned. This note does not propose a change there. It can adopt the same file format later if wanted.

## Open questions for the reviewer

1. Is a per-machine, per-project file enough, or do sessions on different machines need this? A shared version needs a server and an identity model, which is a different and larger design.
2. Should `claims add` require `--agent` to match an allowlist (claude-code, codex, cursor, gemini-cli, human), or stay free-form? Free-form is simpler, an allowlist catches typos.
3. Is cooperative-only acceptable? Nothing stops a session from ignoring a claim.
4. Should the read-only MCP tool exist at all before there is a write path through MCP? Without it, a session that has only MCP cannot see claims.

## Tests (for the implementing PR)

1. Round trip: add, list, renew, done, with an injected clock for expiry.
2. Expired claims are hidden from `list` and pruned on the next write; `list` itself leaves the file byte-identical.
3. Two processes claiming the same slice concurrently: exactly one succeeds. Many concurrent adds with different slices all land (no lost update), checked by spawning threads with the lock.
4. Unix file modes `0600` and `0700`; a symlinked file or directory is refused.
5. Fresh HOME: `list` and the MCP tool create nothing.
6. Canary: a secret value in the vault and environment never appears in any output, file or error; a `slice` that matches a vault secret name or a secret-shaped string is rejected.
7. Validation: bad `agent` label, over-long or non-ASCII `slice`, TTL over 24 hours, more than 64 claims.
8. The MCP tool is read-only: calling it leaves the file byte-identical and creates nothing (the server has no read-only annotation today, so this is checked by test, not by metadata).
9. Corrupt JSON: `list` reports unreadable, exit nonzero for the CLI, no repair.
