# Device code display example

A device code is displayed as `XXXX-XXXX`: eight uppercase letters or numbers
in two groups of four, separated by a hyphen. For example, `ABCD-2345` is a
fictional display with eight code characters and nine displayed characters,
including the hyphen.

The [device form](../apps/web/src/app/device/device-authorization-client.tsx)
shows `XXXX-XXXX` as the field placeholder and this hint below it:

> Enter 8 letters or numbers in the format XXXX-XXXX.

If the entered code has too few or too many letters or numbers, the form
displays this length message:

> Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

See the [Device Auth Wave notes](internal/notes.md#device-auth-wave) for the
source of the display format.
