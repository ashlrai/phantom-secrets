# Device authorization code format

During [cloud login](login.md), the CLI displays a user code for entry on the
device authorization page. A complete code is displayed as `XXXX-XXXX`: eight
uppercase letters or digits in two groups of four, separated by a hyphen. The
separator makes the code easier to read; it is not one of the eight characters.
For example, `ABCD-2345` corresponds to the canonical value `ABCD2345`.
This user code is distinct from the `device_code` used by the CLI for polling.

The page is available only on a commissioned hosted deployment; the presence
of the client and routes does not establish that the public service is active.

## Entering a code

The form formats input as you type or paste. It removes all characters except
ASCII letters (`A`–`Z`, `a`–`z`) and digits (`0`–`9`), converts lowercase
letters to uppercase, and inserts a hyphen after the fourth remaining
character when there are more than four. A typed hyphen, spaces, punctuation,
and non-ASCII characters are removed before formatting. The hyphen is optional
in the input; it need not be in a particular position.

These examples use fictional codes. “Valid” means only that the format passes
the local length check; it does not mean a code was issued or can be approved.

| Input | Displayed | Format valid? |
|-------|-----------|---------------|
| `abcd2345` | `ABCD-2345` | Yes |
| `ab cd-23 45!` | `ABCD-2345` | Yes |
| `ab01-il23` | `AB01-IL23` | Yes |
| `ab-cd` | `ABCD` | No |
| `abcd-23456` | `ABCD-23456` | No |

The form requires exactly eight characters after normalization. An empty,
short, or overlong value shows “Enter 8 letters or numbers. The code is
displayed as XXXX-XXXX.” and does not start authorization. Extra characters
are retained rather than silently truncated, so correct the input and submit
again. The approval request sends the normalized eight-character value without
the display hyphen.

Newly generated codes use a narrower alphabet that excludes `I`, `L`, `O`,
`0`, and `1` to avoid ambiguity. The form's format check still accepts those
ASCII letters and digits; a format-valid value must also match a pending,
unexpired code on the server. If the code expires, start a new login. Only
approve a code from a login you initiated.

Implementation references: [device authorization form](../apps/web/src/app/device/device-authorization-client.tsx),
[normalization helpers](../apps/web/src/lib/device-code.ts), and the
[device auth notes](internal/notes.md#device-auth-wave).
