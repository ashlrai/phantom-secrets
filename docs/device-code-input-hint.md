# Device authorization input hint

The [device authorization form](../apps/web/src/app/device/device-authorization-client.tsx)
labels the field **Device code** and displays the placeholder `XXXX-XXXX`.
The instruction below the field reads:

> Enter 8 letters or numbers in the format XXXX-XXXX.

Submitting an empty, short, or overlong code displays this validation message:

> Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

The form removes characters other than ASCII letters and digits, converts letters
to uppercase, and inserts the display hyphen after the fourth character. It
requires exactly eight letters or digits after normalization; extra characters
are not truncated.
Passing this format check does not establish that a code was issued or can be
approved. See [device authorization code format](device-code-format.md) for
examples and server-side context.

The page is available only on a commissioned hosted deployment.
