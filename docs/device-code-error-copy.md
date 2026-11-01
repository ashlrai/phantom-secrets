# Device code error copy

The [device authorization form](../apps/web/src/app/device/device-authorization-client.tsx)
shows `XXXX-XXXX` as the **Device code** placeholder and displays this hint:

> Enter 8 letters or numbers in the format XXXX-XXXX.

Submitting a code that does not contain exactly eight normalized letters or
numbers displays this validation message:

> Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

The display hyphen is not counted. The form removes characters other than
ASCII letters and digits, converts letters to uppercase, and does not truncate
extra characters. Passing the length check does not establish that a code was
issued or can be approved. See [device authorization code format](device-code-format.md)
for examples and server-side context.
