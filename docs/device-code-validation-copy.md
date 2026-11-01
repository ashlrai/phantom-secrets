# Device code validation copy

The [device authorization form](../apps/web/src/app/device/device-authorization-client.tsx)
displays this format hint below the **Device code** field:

> Enter 8 letters or numbers in the format XXXX-XXXX.

When an empty, short, or overlong code is submitted, it displays this length
error:

> Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

The length check counts normalized ASCII letters and digits; the display hyphen
does not count. Passing the check does not establish that the code was issued
or can be approved. See [device authorization code format](device-code-format.md)
for input examples and server-side context.
