# Landing-page quickstart accessibility review

Use this checklist against the rendered [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx)
and its [`CopyButton`](../apps/web/src/components/landing/CopyButton.tsx). Review
all three platform cards, not just the initial view. Record the browser,
viewport, zoom, input method, assistive technology and any failures; do not
include local secrets, mappings or command output in review notes. This is a
review procedure, not a claim of conformance or a substitute for user testing.

## Controls inventory

The interactive controls a reviewer must find on the section:

- Three platform buttons named "macOS", "Windows" and "Linux" inside the
  group named "Choose an operating system". Each exposes `aria-pressed`.
- Per selected platform card: two archive links named "Download Phantom
  [release] for [platform] [architecture]", two checksum links named
  "Download the SHA-256 checksum for Phantom [release] on [platform]
  [architecture]", a "View exact installer source" link, and one copy
  control whose name starts with "Copy command:" followed by the full
  installer command.
- A "platform installation guide" link in the install note, and two more
  copy controls in the numbered steps, each named "Copy command:" plus its
  command (the two-line `phantom --version` / `phantom-mcp --version` check,
  and `phantom init`).

No two buttons or links may share an accessible name: the copy controls are
distinguished by the commands embedded in their names.

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
      Activating the already-selected platform leaves it pressed: the buttons
      single-select, they do not toggle off.
- [ ] Activate every platform and verify that only its card, heading, archive
      and SHA-256 links, source link, command and caveat are shown. Archive and
      checksum link names identify the platform and architecture. The
      unselected platforms' cards leave the accessibility tree entirely — they
      are unmounted, not visually hidden — so they must not leave tab stops,
      headings or stale announcements behind. The selector buttons themselves
      stay mounted, in the same order, across every selection. The selector is
      a group of buttons, not a tablist; do not expect arrow-key tab behavior.
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
      decorative (`aria-hidden`); copying supplies the command without the
      prompt. Check both numbered commands as well as each installer command:
      the names are long by design, so confirm the assistive technology does
      not truncate them and that each copy control's name is distinct.
- [ ] Test clipboard success and failure: the polite `aria-live` status reports
      “Copied” or “Copy failed; select the command manually”. If copying fails, check
      that the command text can be selected and copied manually. Compare the
      copied text with the displayed command, including line breaks.

## Keyboard access

- [ ] With no mouse, use Tab and Shift+Tab to reach the platform buttons,
      archive and checksum links, installer source, command controls, guide link
      and both step commands in a sensible order. Focus must remain visible.
- [ ] Use Enter and Space to activate platform and copy buttons; use Enter for
      links. Confirm focus remains on the activated button after selection and
      copying, and that continuing Tab from a platform button reaches the
      remaining selector buttons and then the newly displayed card, so
      keyboard users can reach the new content without a mouse.
- [ ] Confirm a keyboard-initiated copy produces the same polite status
      announcement as a pointer click, and that the status clears on its own
      while the control stays usable.
- [ ] Repeat with a screen reader and at a narrow viewport or increased zoom.
      Check announcements, focus visibility, wrapping and manual text selection
      in the target browser: DOM tests alone cannot verify these experiences.

The [command rendering guide](quickstart-command-rendering.md) describes the
copy behavior; the [platform copy review](quickstart-platform-copy-review.md)
covers the meaning of the installation guidance.
