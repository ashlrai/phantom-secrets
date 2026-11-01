# Device code display reference

Reference for how the
[device authorization form](../apps/web/src/app/device/device-authorization-client.tsx)
displays a user code and checks its length, recorded from that component, the
shared [formatting helpers](../apps/web/src/lib/device-code.ts), and the
[Device Auth Wave notes](internal/notes.md#device-auth-wave). Update this page
in the same change as any edit to that display or validation behavior. Every
code shown on this page is fictional; do not record real codes here.

## Displayed format

A complete user code is displayed as `XXXX-XXXX`: eight uppercase ASCII
letters or digits in two groups of four, separated by a hyphen. The hyphen is
a readability separator, not a ninth code character, so a complete code has
eight code characters and nine displayed characters. For example, the
fictional display `ABCD-2345` corresponds to the canonical value `ABCD2345`
that approval submits and `device_tokens.user_code` stores.

The displayed user code is the one the initiation API formats and the CLI
prints during [cloud login](login.md). It is distinct from the `device_code`
the CLI uses to poll for authorization, which is never displayed.

## Formatting as it is typed

The form renders each edit through `formatDeviceUserCode` rather than
truncating or masking input. The formatter first normalizes the value —
removing every character that is not an ASCII letter or digit, including
typed hyphens, spaces, and punctuation, and converting letters to uppercase —
then inserts the display hyphen after the fourth character when more than
four remain:

| Typed or pasted input | Displayed |
|-----------------------|-----------|
| `abcd` | `ABCD` |
| `abcde` | `ABCD-E` |
| `abcd2345` | `ABCD-2345` |
| `ab cd-23 45!` | `ABCD-2345` |
| `abcd23456` | `ABCD-23456` |

Extra characters are retained, so overlong input stays visible and invalid
instead of mutating into a different valid code.

## Length validation

Submitting the form runs `isValidDeviceUserCode`, which requires exactly
eight normalized ASCII letters or digits; the display hyphen is not counted.
The check runs before any sign-in or network work, so an empty, short, or
overlong submission — `ABCD-234` or `ABCD-23456` in the fictional examples
above — fails closed with the length error and starts neither GitHub OAuth
nor an approval request:

> Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

The same rule applies after a GitHub return: a stored code that is missing or
does not normalize to eight characters is rejected before approval, and the
form asks for the current terminal code. A format-valid code is not
necessarily an issued or approvable one; the approve route checks the
normalized value against pending, unexpired rows.

## Sources and related pages

- [Device authorization form](../apps/web/src/app/device/device-authorization-client.tsx) —
  placeholder, hint and error copy, submit guard, and OAuth-return handling
- [Formatting helpers](../apps/web/src/lib/device-code.ts) —
  `DEVICE_USER_CODE_LENGTH`, `normalizeDeviceUserCode`,
  `formatDeviceUserCode`, `isValidDeviceUserCode`
- [Device Auth Wave notes](internal/notes.md#device-auth-wave) — display and
  canonical-storage source of the format
- [Device authorization code format](device-code-format.md) — input examples
  and server-side context
- [Device user-code display contract](device-code-display-contract.md) —
  normalization, lookup, and migration contract

The page is available only on a commissioned hosted deployment; the presence
of the client and routes does not establish that the public service is
active.
