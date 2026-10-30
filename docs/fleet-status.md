# `phantom fleet-status --json` schema

`phantom fleet-status` is a read-only, value-free view of the whole fleet of
managed secrets: each secret's name, expiry state, last stored validation
result, and rotation-schedule posture, plus the sorted list of names whose
rotation is overdue.

The command never reads a secret value. It inspects only vault names and
metadata (`list_with_metadata`, `get_validation_metadata`, `backend_name`),
contacts no provider, and writes nothing — the report is safe to hand to
agents and CI.

## Flags

| Flag | Effect |
|---|---|
| `--json` | Print the document below instead of the human table. The global `phantom --json` flag works too. |
| `--expiring-within DAYS` | Window for `expiry.state == "expiring_soon"` (default `7`). |
| `--strict` | Print the report, then exit `2` when `needs_attention` is `true` — any secret's `attention` flag is set, or the inventory is partial. Exit `1` stays a command error, never an issues-found result. |

## Inventory guard

An answer built from the vault inventory never reads an empty OS keychain as
"no secrets" when a locked encrypted-file vault exists for the project: the
command refuses (`Vault locked: …`, exit 1) rather than reporting an empty,
healthy fleet. When the keychain does list entries beside that locked file,
the command still reports — `inventory` reads `partial_keychain_only`, the
limitation is printed to stderr as a warning, and `--strict` treats it as
needs-attention.

## Schema (version 1)

```json
{
  "schema": "phantom.fleet_status.v1",
  "kind": "phantom.fleet_status.v1",
  "generated_at": 1800000000,
  "expiring_within_days": 7,
  "inventory": "complete",
  "vault_backend": "encrypted-file",
  "secrets": [
    {
      "name": "staging/API_KEY",
      "environment": "staging",
      "detected_service": "openai",
      "attention": true,
      "expiry": {
        "state": "expired",
        "expires_at": 1799000000,
        "days_remaining": -1,
        "read_only": true
      },
      "validation": {
        "state": "invalid",
        "checked_at": 1799900000,
        "stale": false,
        "validator": "openai",
        "failure_reason": "provider rejected the credential"
      },
      "rotation": {
        "state": "overdue",
        "schedule": "every 30 days",
        "enforced": true,
        "anchor": 1792000000,
        "age_days": 92,
        "due_at": 1794592000
      }
    }
  ],
  "overdue_rotations": ["staging/API_KEY"],
  "needs_attention": true,
  "summary": {
    "secrets": 1,
    "expired": 1,
    "expiring_soon": 0,
    "read_only": 1,
    "validation_invalid": 1,
    "validation_unreachable": 0,
    "validation_never_checked": 0,
    "validation_stale": 0,
    "rotation_overdue": 1,
    "rotation_unknown_age": 0,
    "rotation_schedule_errors": 0,
    "overdue_rotations": 1,
    "needs_attention": 1
  }
}
```

## Top-level fields

| Field | Values |
|---|---|
| `schema` | `phantom.fleet_status.v1`. The envelope id to key on; the `.vN` suffix changes only when the JSON shape breaks. |
| `kind` | Same string as `schema`, carried inside the document. |
| `generated_at` | Unix seconds; when the report was built. |
| `expiring_within_days` | The `--expiring-within` window used. |
| `inventory` | `complete` or `partial_keychain_only` (see Inventory guard). |
| `vault_backend` | `VaultBackend::backend_name` of the opened vault (e.g. `encrypted-file`, `keychain`). |
| `secrets` | One row per vault entry, sorted by `name`. |
| `overdue_rotations` | Sorted names where `expiry.state == "expired"` or `rotation.state == "overdue"`. |
| `needs_attention` | `true` when any secret's `attention` flag is set or the inventory is partial — the condition `--strict` exits `2` on. |
| `summary` | Headline counts; `needs_attention` counts flagged secrets, `overdue_rotations` counts the list. |

## Per-secret fields

| Field | Values |
|---|---|
| `name` | Exact vault entry name. Scoped entries keep the `env/NAME` form. Never a value, mapping, or credential. |
| `environment` | The `env` prefix parsed from `name`; `default` for bare names. |
| `detected_service` | The `[services.*]` name whose `secret_key` matches the entry's logical name, else `null`. |
| `attention` | `true` when the secret needs operator action: `expiry.state == "expired"`, `expiry.read_only`, `validation.state == "invalid"`, or `rotation.state` in `overdue`, `unknown_age`, `schedule_error`. |

### `expiry`

From vault lifecycle metadata only (`SecretMetadata`), the same source
`phantom secrets-expiring-soon` and `expiry enforce` read.

| Field | Values |
|---|---|
| `state` | `none` (no `expires_at`), `valid`, `expiring_soon` (`0 <= days_remaining <= expiring_within_days`), `expired` (`days_remaining < 0`). |
| `expires_at` | Stored expiry instant (Unix seconds), `null` when unset. |
| `days_remaining` | Whole days until expiry, floored; negative when expired (`-1` covers anything within the last day). `null` when unset. |
| `read_only` | `true` when the entry was demoted to `read_only` by the expiry policy; `phantom exec`/`sync` refuse to hand it out. |

### `validation`

The persisted result of the last `phantom validate` or scheduler check. No
credential is re-checked; `never_checked` is reported verbatim rather than
treated as healthy.

| Field | Values |
|---|---|
| `state` | `never_checked` (no stored result), `valid`, `invalid` (provider rejected it), `unreachable` (check could not reach the provider). |
| `checked_at` | Unix time of the stored check; `null` when `never_checked`. |
| `stale` | `true` when a checked result is older than 24 h (`DEFAULT_STALE_SECS`). Always `false` for `never_checked` — unknown is not stale. |
| `validator` | Validator that produced the stored result, when recorded; `null` otherwise. |
| `failure_reason` | Stored reason for `invalid`/`unreachable` results; `null` otherwise. Persisted by validators as a value-free string. |

`unreachable` is derived from the stored record the same way `phantom
validate` writes it: `is_valid == false` with a `failure_reason` starting
`unreachable:`.

### `rotation`

Age judged the same way the `enforce_rotation_on_access` access gate judges
it — the later of the entry's `created_at` and `rotated_at` vault metadata
(the schedule's `last_rotated` in `.phantom.toml` is never trusted) — but
reported for every secret, not only enforced ones.

| Field | Values |
|---|---|
| `state` | `no_schedule` (no resolvable schedule period; includes a `never` policy), `within_period`, `overdue` (age ≥ one schedule period), `unknown_age` (no anchor, or an anchor in the future), `schedule_error` (`rotate_every` does not parse — a config defect, reported not hidden). |
| `schedule` | Effective schedule label (`weekly`, `every 30 days`, `never`) from per-secret override or global `[phantom.rotation_policy]`; `null` when none. |
| `enforced` | `true` when `[phantom.secrets.NAME] enforce_rotation_on_access = true` — the access gate actually applies the schedule to this secret. |
| `anchor` | Unix timestamp the age is measured from; `null` when the entry records no `created_at`/`rotated_at`. |
| `age_days` | Whole days since the anchor; `null` when `unknown_age`. |
| `due_at` | Unix time the value ages past one schedule period; `null` when the state is `no_schedule`, `unknown_age`, or `schedule_error`. |

## Never appears

Secret values, `phm_` mappings, session tokens, passphrases, provider
credentials, `.env` contents, and file paths. Rows carry names and metadata
timestamps only. The integration test
`crates/phantom-cli/tests/fleet_status_q8.rs` pins this: it plants fake
fixture values and asserts none of them — and no `phm_` string — appears on
stdout or stderr, in JSON or human output, on success or failure.
