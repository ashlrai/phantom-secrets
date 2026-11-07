# Device code readability

How the device authorization user code is shown to people, and why the shown
form differs from the stored one.

## Display format

The user code contains eight uppercase letters or digits. For human-readable
display it is formatted as `XXXX-XXXX`: two groups of four code characters
separated by a hyphen. The hyphen is a readability separator only, so
`ABCD-2345` has eight code characters and nine displayed characters including
the separator.

## Display versus storage

| Form | Example | Where |
| --- | --- | --- |
| Displayed | `ABCD-2345` | CLI login output, browser authorization form |
| Canonical | `ABCD2345` | `device_tokens.user_code`, approval lookup |

The hyphen is not part of the canonical value.

## Input handling

- The browser strips non-alphanumeric characters and uppercases input before
  formatting it.
- Approval submits and looks up the canonical form.
- Incomplete or overlong normalized codes are invalid; extra characters are not
  silently truncated.

## Not to be confused with `device_code`

The CLI prints the user code for entry in the browser. The separate
`device_code` returned by the initiation API is what the CLI uses for polling,
and is never shown for typing.

## Where it lives

- CLI: `crates/phantom-cli/src/commands/login.rs`
- Browser form: `apps/web/src/app/device/device-authorization-client.tsx`
- Shared helpers: `apps/web/src/lib/device-code.ts`

Source: [Device Auth Wave notes](internal/notes.md#device-auth-wave).
