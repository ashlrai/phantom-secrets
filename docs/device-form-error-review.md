# Device form error review

Review the [device authorization form](../apps/web/src/app/device/device-authorization-client.tsx)
with synthetic codes in a local test environment. The `/device` page shows the
form only when the hosted personal-vault service is commissioned; otherwise it
shows an unavailable message. The [interaction test](../apps/web/tests/device-validation-interaction.test.cjs)
renders the form with authentication and network calls mocked.

## Reproduce the error

1. Leave **Device code** empty, or enter `ABCD-234` (seven letters or numbers).
   Submit **Authorize Device** by button or Enter. The form displays:

   > Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

2. The input remains editable and the entered code remains in place. The
   separator does not count toward the eight-character requirement; a code
   with more than eight letters or numbers also produces this error. Invalid
   length is rejected before sign-in or approval is attempted.
3. Editing alone does not clear the error. On a valid-format submission the
   form clears it and begins authentication; use mocks when checking this path.

## Check the association

After the invalid submission, inspect the **Device code** input in browser
developer tools. Its `aria-invalid` should be `true`, and its
`aria-describedby` should include `device-error` alongside the hint and help
IDs. The visible message should have `id="device-error"` and `role="alert"`.
Before submission, the input should not reference `device-error` and no alert
should be present. Verify the label still identifies the input, then revisit
the input with a screen reader and check that the error is available as its
description and that the invalid state is conveyed. Check announcement on
submission as well; DOM attributes alone do not prove screen-reader behavior.
Record the browser, OS and assistive technology used and the observed result.

The [validation interaction test](../apps/web/tests/device-validation-interaction.test.cjs)
checks the rendered message, invalid state, association and absence of auth
or network calls for invalid submissions. It does not replace a manual
assistive-technology review.
