# Landing-page quickstart accessibility review

Use this checklist against the rendered [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx)
and its [`CopyButton`](../apps/web/src/components/landing/CopyButton.tsx). Review
all three platform cards, not just the initial view. Record the browser,
viewport, zoom, input method, assistive technology and any failures; do not
include local secrets, mappings or command output in review notes. This is a
review procedure, not a claim of conformance or a substitute for user testing.

## Headings and structure

- [ ] Find the named install region using “Install on your OS. Then protect one
      project.” Its visible heading is an `h2` and names the section through
      `aria-labelledby`.
- [ ] For each selected OS, find its `h3` and the two subsequent `h3` step
      headings: “Verify both [release] binaries” and “Protect one supported
      project”. The steps form an ordered list; their decorative numbers and
      the platform icon are hidden from assistive technology.
- [ ] Confirm that the receipts are labeled illustrative and are distinguishable
      from instructions and actual local results.

## Platform selection

- [ ] Find the group named “Choose an operating system” and its macOS, Windows
      and Linux buttons. macOS starts selected. Each button exposes its current
      `aria-pressed` state; exactly one is pressed after each selection.
- [ ] Activate every platform and verify that only its card, heading, archive
      and SHA-256 links, source link, command and caveat are shown. Archive and
      checksum link names identify the platform and architecture. The selector
      is a group of buttons, not a tablist; do not expect arrow-key tab behavior.
- [ ] Check that the selected state is visually discernible and announced by
      the assistive technology in use. Keyboard focus stays on the activated button;
      the changed card is not a live announcement, so navigate to it to review it.

## Command readability

- [ ] On every card, read the entire multiline installer command, including
      punctuation, line breaks and indentation. Check narrow viewports and zoom:
      visual wrapping must not hide or alter command text. Inspect contrast and
      text size, including the smaller installer command, rather than assuming
      the styles are readable in every setting.
- [ ] The copy control's accessible name starts with “Copy command:” and
      includes the command. The visible `$` or `PS>` prompt and copy icon are
      decorative; copying supplies the command without the prompt. Check both
      numbered commands as well as each installer command.
- [ ] Test clipboard success and failure: the polite status reports “Copied”
      or “Copy failed; select the command manually”. If copying fails, check
      that the command text can be selected and copied manually. Compare the
      copied text with the displayed command, including line breaks.

## Keyboard access

- [ ] With no mouse, use Tab and Shift+Tab to reach the platform buttons,
      archive and checksum links, installer source, command controls, guide link
      and both step commands in a sensible order. Focus must remain visible.
- [ ] Use Enter and Space to activate platform and copy buttons; use Enter for
      links. Confirm focus remains on the activated button after selection and
      copying, and that keyboard users can reach the newly displayed card.
- [ ] Repeat with a screen reader and at a narrow viewport or increased zoom.
      Check announcements, focus visibility, wrapping and manual text selection
      in the target browser: DOM tests alone cannot verify these experiences.

The [command rendering guide](quickstart-command-rendering.md) describes the
copy behavior; the [platform copy review](quickstart-platform-copy-review.md)
covers the meaning of the installation guidance.
