# Device code validation copy

The [device authorization form](../apps/web/src/app/device/device-authorization-client.tsx)
displays this format hint below the **Device code** field:

> Enter 8 letters or numbers in the format XXXX-XXXX.

When the user submits an empty, short, or overlong code, the form displays this
length error:

> Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

The form formats input as it is entered: it removes everything except ASCII
letters and digits, uppercases the remainder, and inserts a display hyphen
after the fourth character. The [length check](../apps/web/src/lib/device-code.ts)
counts the remaining ASCII letters and digits, excluding the hyphen, and
requires exactly eight. For example, `ABCD-234` is too short and `ABCD-23456`
is too long.

The error appears on submission, before sign-in or an approval request starts.
Editing the field does not immediately clear it; submitting a code that passes
the length check clears it and continues authorization. A format-valid code
may still be rejected by the server. A missing or invalid stored code after an
OAuth return instead shows a separate instruction to enter the current code.
See [device authorization code format](device-code-format.md) for more input
examples and server-side context.
