# Device authorization page UI

During [cloud login](login.md), the CLI prints a user code and directs the
operator to the hosted `/device` page. This guide describes what that page
renders — the displayed code format, the local validation message, and each
user-visible submission state — as implemented by
[device-authorization-client.tsx](../apps/web/src/app/device/device-authorization-client.tsx).
Entry and normalization rules are specified in
[device-code-format.md](device-code-format.md). Credential handling is
intentionally out of scope: nothing below covers how sign-in material or the
submitted code is stored, attached, or transmitted.

The page is available only on a commissioned hosted deployment; the presence
of the client and routes does not establish that the public service is
active. An uncommissioned deployment renders an informational notice instead
of the form (see [page.tsx](../apps/web/src/app/device/page.tsx)).

## Page layout

The form sits on a centered card under the Phantom Secrets brand link
(`/secrets`), with a "Back to Phantom" link (`/`) below it. In its idle
state the card shows:

- the heading "Authorize Device";
- the instruction "Enter the code shown in your terminal to authorize this
  device with Phantom Cloud.";
- a "Device code" label above a single autofocused text field with the
  placeholder `XXXX-XXXX` (`autoComplete="off"`,
  `autoCapitalize="characters"`, `spellCheck={false}`);
- the hint "Enter 8 letters or numbers in the format XXXX-XXXX.";
- the footer help "This will sign you in via GitHub and link this device to
  your Phantom account.";
- a full-width submit button reading "Authorize Device".

## Displayed code format

The field echoes the code as `XXXX-XXXX`: up to four characters, a hyphen,
then the remaining characters, rendered centered in monospace with wide
letter spacing. The component reformats on every change, applying the rules
in [device-code-format.md](device-code-format.md): characters other than
ASCII letters and digits are removed, lowercase letters become uppercase,
and the hyphen is inserted after the fourth remaining character once more
than four remain. Characters beyond eight are retained and shown rather
than truncated, so an overlong entry displays as `ABCD-23456` until
corrected. The field has no `maxlength`.

## Validation message

Submitting runs a local check first: the normalized entry must be exactly
eight characters. An empty, short, or overlong value leaves the form in its
input state and shows a `role="alert"` message:

> Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

While the message is visible the field carries `aria-invalid="true"` and
its `aria-describedby` adds the alert's id alongside the hint and help ids.
The button stays enabled — the check fails closed on submit rather than
disabling the control. The alert remains on screen while the entry is
corrected and clears on the next submission attempt that passes the check;
a failed local check starts no sign-in or authorization work.

## Submission states

The component renders one status at a time.

| Status | What the operator sees |
|--------|------------------------|
| `input` | Idle entry state: the field and the "Authorize Device" button are enabled. Every failure also returns here with an alert message. |
| `authenticating` | Reached by a format-valid submission while sign-in is resolved. The field and button are disabled, the button reads "Signing in with GitHub...", and the card reports `aria-busy`. An operator who is not signed in is sent to GitHub and returned to this page, where approval resumes without another click when the earlier code is still usable. |
| `approving` | Reached while the approval is in flight. The field and button remain disabled and the button reads "Approving...". |
| `done` | The form is replaced by a `role="status"` confirmation: a green check icon, the heading "Device Authorized", the text "You can return to your terminal. The CLI will log you in automatically.", and an "Open your dashboard" link to `/dashboard`. |

A screen-reader-only `role="status"` line mirrors the busy states, reading
"Signing in with GitHub." during `authenticating` and "Approving your
device." during `approving`.

## Failure alerts

Every failure returns the form to `input`, re-enables the field and button,
and renders one `role="alert"` message:

| Message | Shown when |
|---------|------------|
| `Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.` | The normalized entry is not exactly eight characters; checked locally before anything else runs. |
| The service's own error, or `Failed to approve device` | The approval was rejected, for example for an expired or unrecognized code. |
| `Failed to connect. Please try again.` | The approval request could not be completed. |
| `Unable to read your sign-in session. Please try again.` | The existing sign-in state could not be read. |
| `GitHub sign-in could not start. Please try again.` | The redirect to GitHub could not begin. |
| `GitHub sign-in did not complete. Please try again.` | The page could not confirm a completed GitHub sign-in after returning. |
| `Unable to complete sign-in. Please try again.` | Finishing sign-in failed. |
| `Sign-in completed. Enter the current code from your terminal to authorize this device.` | Sign-in finished but the page could not restore the code entered beforehand; enter the code shown in the terminal again. |

Implementation references:
[device authorization client](../apps/web/src/app/device/device-authorization-client.tsx),
[code helpers](../apps/web/src/lib/device-code.ts),
[format specification](device-code-format.md), and
[cloud login](login.md).
