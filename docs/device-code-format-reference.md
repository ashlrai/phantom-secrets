# Device code format reference

Exact copy recorded from the
[device authorization form](../apps/web/src/app/device/device-authorization-client.tsx).
Update this page in the same change as any edit to those strings.

## Field label and placeholder

The form labels the field **Device code** (`htmlFor="device-code"`) and the
`placeholder` attribute on the `device-code` input displays `XXXX-XXXX`.

## Static format hint

The `#device-code-hint` paragraph below the field reads:

> Enter 8 letters or numbers in the format XXXX-XXXX.

## Length-error copy

`handleSubmit` runs `isValidDeviceUserCode(code)` before any sign-in or
network work. When the normalized value is not exactly eight letters or
digits, `#device-error` (rendered with `role="alert"`) displays:

> Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

## Counting rules

The length check counts normalized ASCII letters and digits in
[device-code.ts](../apps/web/src/lib/device-code.ts); the display hyphen is
not counted, and extra characters are retained rather than truncated.
Passing the check does not establish that a code was issued or can be
approved. See [device authorization code format](device-code-format.md) for
input examples and server-side context.

The page is available only on a commissioned hosted deployment.
