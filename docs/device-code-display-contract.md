# Device user-code display contract

The user code shown by the initiation API and CLI, and entered on the device
authorization page, is a human-readable representation of a canonical user
code. A complete display is `XXXX-XXXX`: eight uppercase ASCII letters or
digits in two groups of four. The hyphen is a readability separator, not a
ninth code character. For example, the fictional display `ABCD-2345` represents
the canonical value `ABCD2345` stored in `device_tokens.user_code`.

The user code is distinct from the `device_code` used by the CLI to poll for
authorization. The initiation API returns the formatted user code; the CLI
prints it for entry in the browser.

## Input and lookup

The browser removes non-ASCII-alphanumeric characters, uppercases the
remaining letters, and displays a hyphen after the fourth character when
there are more than four. Approval submits and looks up the normalized form
without the separator. A complete normalized code must have exactly eight
characters; incomplete and overlong input is invalid, and extra characters
are not silently truncated. Format validity alone does not mean a matching
pending, unexpired code exists.

Newly issued codes use a narrower alphabet that excludes `I`, `L`, `O`, `0`,
and `1`. The input format check accepts all ASCII letters and digits. See the
[format guide](device-code-format.md) for input examples and form behavior.

## Stored values and migration

The [canonical user-code migration](../apps/web/supabase/migrations/20260523000016_canonical_device_user_codes.sql)
uppercases existing values and removes hyphens. This historical migration is
not the browser's general input normalization: it does not remove every
non-alphanumeric character. It expires stale pending rows and all but the
newest pending row for each canonical code, then creates a unique index on
`user_code` for pending rows only. That index is not a uniqueness guarantee
across every status.

The [device auth notes](internal/notes.md#device-auth-wave),
[formatting helpers](../apps/web/src/lib/device-code.ts), and
[authorization form](../apps/web/src/app/device/device-authorization-client.tsx)
describe the corresponding implementation. The hosted device page requires a
commissioned deployment; these sources do not establish public availability.
