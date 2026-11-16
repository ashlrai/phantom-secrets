# DeepWiki configuration

[DeepWiki](https://deepwiki.com/ashlrai/phantom-secrets) generates architecture
pages and diagrams from this repository. The file
[`.devin/wiki.json`](../.devin/wiki.json) steers what it generates.

## Format

- `repo_notes`: free-text guidance (each entry has a `content` string) about the
  project, preferred diagram topics, and what must not be documented.
- `pages`: ordered page outline. Each page has a `title` and `purpose`, plus an
  optional `parent` naming another page's `title` to nest it.

## Rules for editing

- Keep valid JSON; check with
  `python3 -m json.tool .devin/wiki.json`.
- Every `parent` must match an existing page `title`.
- Never put secret values, tokens, or real home-directory paths in notes.
- Generated pages are orientation only. [architecture.md](architecture.md),
  [THREAT_MODEL.md](../THREAT_MODEL.md), and source are authoritative; update
  `wiki.json` when crates or trust boundaries change.
