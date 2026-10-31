# Workbench audit feed

`phantom audit feed < audit.ndjson` reads stdin until EOF and emits one JSON
object per accepted newline-terminated record. `--json` is also accepted.
It opens no vault, reads no implicit audit path, and makes no network requests.

The stdin projection of schema version 1 has exactly five fields: `schema_version` (1), `type`
(`phantom.audit`), `seq` and `ts` (unsigned 64-bit integers, timestamp in Unix
seconds), and `operation`. Operation labels are `vault.store`, `vault.retrieve`,
`vault.delete`, `cloud.push`, `cloud.pull`, `proxy.response_leak`, or `unknown`.
Operation and type strings come from the adapter's fixed vocabulary. Names, mappings,
values, process metadata, encrypted context, signatures, and unknown fields
are never forwarded. Consumers must tolerate `unknown` operations.

Malformed records, missing or mistyped required fields, records exceeding
64 KiB including the newline, and an unterminated final record are discarded.
The adapter resumes at the next newline after an oversized record, keeps
bounded record memory, and flushes each emitted event for streaming readers.
Input/output errors fail the command. The projection does not authenticate
records or verify the audit HMAC chain; use `phantom audit verify` separately.

## Follow and resume

`phantom audit feed --follow /path/to/audit.log` polls the explicit file every
100 ms and flushes accepted events immediately. Each event adds an opaque
`cursor` string. Save it after processing the event, then reconnect with
`phantom audit feed --follow /path/to/audit.log --cursor "$saved_cursor"`.
Cursors contain versioned file identity, a byte offset after a complete line,
and a SHA-256 prefix digest; they contain no source strings or paths. They are
positions, not authentication or evidence of audit integrity.

A matching cursor resumes after its event. Truncation, changed prefix, or file
replacement restarts at byte zero; consumers must tolerate duplicate events.
Rotation follows the current path, waiting if it temporarily disappears; unread
events in the renamed file cannot be recovered. Partial lines wait for their
newline. Malformed and oversized lines retain the same filtering as stdin.
Prefix checks use bounded memory but reread the consumed prefix every poll;
use bounded, rotated logs. Stop the follower with the normal process signal.
