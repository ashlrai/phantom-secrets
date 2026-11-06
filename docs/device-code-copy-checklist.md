# Device code copy checklist

Use this checklist when reviewing copy in the [device authorization form](../apps/web/src/app/device/device-authorization-client.tsx). The strings below are the current displayed copy; update this checklist alongside any approved copy change.

- [ ] **Placeholder** in the Device code field: `XXXX-XXXX`
- [ ] **Length error** shown after submitting a code that does not contain exactly eight normalized letters or numbers:

  > Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

The display hyphen is not counted. Input is normalized to ASCII letters and digits, and extra characters are retained. The error appears before sign-in or an approval request; a code that passes the length check can still be rejected by the server. See the [format reference](device-code-format-reference.md) for the field hint and further context.
