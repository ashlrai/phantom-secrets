# Value-blind agent usage audit

`phantom exec` and the MCP stdio server require audit records for credential
operations. Explicit `PHANTOM_ENGINE_ID` attribution also activates required
logging, even when `PHANTOM_AUDIT` is unset. Other terminal workflows retain
the existing `PHANTOM_AUDIT=1` (best effort) and `required` modes.

Records append to the existing private, locked, HMAC-chained
`~/.phantom/audit.log`; no second log or independent integrity scheme is used.
The existing sequence, timestamp, operation, secret `name`, process metadata,
and HMAC fields remain compatible with older signed logs. New records include:

| Field | Meaning |
| --- | --- |
| `ts` | UNIX timestamp in seconds |
| `actor` | Known engine ID, `exec`, `mcp`, or `phantom` |
| `name` | Secret name, never its value; absent when refusal precedes secret selection |
| `route` | Configured route identifier; empty for non-route operations |
| `host` | Upstream hostname without userinfo, port, path or query; empty for non-route operations |
| `outcome` | `attempted`, `success`, `failure`, `admitted`, or `refused` |

Create/store, get, injection retrieval and compare-and-swap operations are
instrumented in both file and keychain backends. CLI and MCP local token
remaps record each affected name. Provider credential rotation remains subject
to the existing release's hard denial and consent controls.

An identified agent operation records `attempted` durably before credential
access, then `success` or `failure`. A process crash may leave an attempt
without a terminal record. A successful compare-and-swap API call can return
false (no mutation); `success` describes completion of the API call.
An audit error after a committed mutation is reported as an error: reconcile
state before retrying. Audit failures before admission prevent credential
access or mutation. Error text and return values are never passed to the
recorder.

Every credential-bearing proxy dispatch records `proxy.use` with outcome
`admitted` before sending. This is an injection admission receipt, not a claim
that an upstream service accepted the credential or completed the request.
The recorder receives configured route metadata only, never client paths,
queries, headers, bodies, tokens, values, or upstream error text.

Set `PHANTOM_ENGINE_ID` outside the agent to one of `codex`, `claude`, `cursor`,
`windsurf`, `gemini`, or `copilot`. The reserved source labels `exec` and
`mcp` are also recognized. Exec children inherit required auditing and the
explicit engine label (or `exec` by default). An unknown identifier is recorded with
`engine.refused`, outcome `refused`, and actor
`unknown:sha256:<fingerprint>`, then refused before credential access or
proxy dispatch. Fingerprinting preserves correlation without accepting
arbitrary environment text into the log. Engine labels are attribution,
not authenticated identities; an agent with authority over its environment
can change a label. They do not replace MCP approvals or trusted-terminal
consent. Exec and MCP still require auditing when this variable is absent.

Query all timestamped events as JSON Lines, in append order:

```sh
phantom audit --json
phantom audit --json --since 1792972800
```

`--since` is an inclusive UNIX-seconds bound and applies to the default query,
not the existing subcommands. Empty results produce empty stdout. Chain
markers are omitted. Queries stream under a shared lock, reject symlinks and
malformed records, and create no files when the log is absent. Query output
is not an integrity verdict; use `phantom audit verify --json` to verify the
chain. The existing `show`, `tail`, `stats` and export subcommands remain
available. Secret names and other audit metadata remain sensitive: protect
exports accordingly.
