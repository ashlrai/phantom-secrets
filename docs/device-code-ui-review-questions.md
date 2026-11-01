# Device code UI review questions

Use these questions to review the [device authorization form](../apps/web/src/app/device/device-authorization-client.tsx).
They are review prompts, not claims that the current UI passes. Record the
browser, OS, viewport, zoom, assistive technology, and result for each check;
include a screenshot or contrast measurement when useful. Use synthetic codes
and mocked failures in a local or test environment, never real credentials.
The hosted page requires a commissioned deployment.

## Placeholder and instructions

The empty field is labeled **Device code**, has the placeholder `XXXX-XXXX`,
and has a separate hint below it:

> Enter 8 letters or numbers in the format XXXX-XXXX.

1. On initial load, including with autofocus, can you distinguish the
   placeholder from entered text and read all of it against the input background?
   Measure placeholder contrast and record whether it reaches 4.5:1.
2. After typing `abcd234`, does the visible value become `ABCD-234`, and can
   you still find the label and format hint once the placeholder disappears?
   After clearing the field, does the placeholder return?
3. At a 320 CSS-pixel viewport and at 200% and 400% browser zoom, are the field,
   placeholder, label and hint readable without clipping or horizontal page
   scrolling? Repeat in forced-colors mode if available.
4. Using keyboard navigation and a screen reader, is the field identified as
   Device code and is the format hint available when it receives focus? Can
   the task be understood without relying on the placeholder alone?

## Errors and recovery

Submit an empty field, then a short code such as `ABCD-234`. Both should show:

> Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.

1. Is the entire error readable against the card background at normal size,
   narrow width, 200% and 400% zoom, and in forced-colors mode? Measure its
   text contrast and record whether it reaches 4.5:1. Is the problem conveyed
   without relying only on red text?
2. With a screen reader, is the error announced on submission and available
   again when revisiting the field? Does the field convey its invalid state?
   Check both mouse and keyboard submission.
3. Can a user tell how to correct the code? After editing, is it clear that
   the error remains until a valid-format code is submitted again? On that
   retry, does the old error clear while authorization is in progress?
4. With a mocked connection failure on approval, is the following message
   readable, announced, and understandable as a reason to retry?

   > Failed to connect. Please try again.

5. With mocked approval responses, are longer server-provided errors readable
   and actionable without clipping or overlap? Include an invalid/expired code
   and an uncertain approval, where the user should check the terminal before
   retrying. Do not assume every approval failure means no approval occurred.

The existing [placeholder](../apps/web/src/app/device/device-code-placeholder.test.tsx)
and [accessibility](../apps/web/src/app/device/device-code-accessibility.test.tsx)
tests cover DOM semantics and interactions; they do not measure rendered contrast,
layout, or actual screen-reader announcements. See the
[format reference](device-code-format-reference.md) for the exact copy and
counting rules.
