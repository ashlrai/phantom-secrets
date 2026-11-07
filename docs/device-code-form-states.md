# Device authorization form states

The [device authorization client](../apps/web/src/app/device/device-authorization-client.tsx)
lets a user approve the code shown by their terminal. The
[device page](../apps/web/src/app/device/page.tsx) renders this form only when
personal vaults are commissioned on the hosted deployment; otherwise it shows
an unavailable message. The component's presence does not imply that a hosted
service is available.

## Input and validation

The initial **Authorize Device** form has an auto-focused **Device code** text
field, the `XXXX-XXXX` placeholder, a format hint, an **Authorize Device**
button, and help explaining the GitHub sign-in and account link. The field
formats each edit: it keeps only ASCII letters and digits, uppercases letters,
and inserts a hyphen after the fourth character when needed. It does not
truncate excess characters. See the [format guide](device-code-format.md) for
examples and the distinction between format validity and an issued code.

Submitting an empty, short, or overlong normalized value leaves the form
editable and shows:

> Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

No sign-in or approval request starts for that submission. The error is an
alert and is associated with the field, which is marked invalid. Editing does
not immediately clear the error; a subsequent format-valid submission clears
it before sign-in starts. The hint and help remain associated with the field.

## Submission and return

| State | What is shown | What happens next |
| --- | --- | --- |
| Authenticating | The input and button are disabled; the button reads **Signing in with GitHub...**. The section is busy, and a screen-reader status announces “Signing in with GitHub.” | An existing session can proceed to approval; otherwise GitHub sign-in starts. The code is kept in tab session storage for the return. |
| Approving | The input and button remain disabled; the button reads **Approving...**. The section is busy, and a screen-reader status announces “Approving your device.” | The client submits the normalized code for approval. |
| Done | **Device Authorized** replaces the form, with instructions to return to the terminal and an **Open your dashboard** link. | The CLI can complete login. |

On a GitHub return, the form can restore the stored code and authenticate
before approval. If sign-in succeeds but the stored code is missing or invalid,
the form asks the user to enter the current terminal code. Sign-in failures,
approval errors, and connection failures return to the editable form with an
alert; an approval response may supply its own error message. The user can
correct the code or retry. Only approve a code from a login you initiated.
