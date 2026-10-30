# Workbench audit feed

`phantom audit feed < audit.ndjson` reads stdin until EOF and emits one JSON
object per accepted newline-terminated record. `--json` is also accepted.
It opens no vault, reads no implicit audit path, and makes no network requests.

Schema version 1 has exactly five fields: `schema_version` (1), `type`
(`phantom.audit`), `seq` and `ts` (unsigned 64-bit integers, timestamp in Unix
seconds), and `operation`. Operation labels are `vault.store`, `vault.retrieve`,
`vault.delete`, `cloud.push`, `cloud.pull`, `proxy.response_leak`, or `unknown`.
All output strings come from the adapter's fixed vocabulary. Names, mappings,
values, process metadata, encrypted context, signatures, and unknown fields
are never forwarded. Consumers must tolerate `unknown` operations.

Malformed records, missing or mistyped required fields, records exceeding
64 KiB including the newline, and an unterminated final record are discarded.
The adapter resumes at the next newline after an oversized record, keeps
bounded record memory, and flushes each emitted event for streaming readers.
Input/output errors fail the command. The projection does not authenticate
records or verify the audit HMAC chain; use `phantom audit verify` separately.
