### Security (`phantom check --staged` scans `#` lines inside quoted values)

- The staged credential-shape scan of `.env`, `.env.*` templates and `.envrc`
  skipped every added line that looked like a credential comment on its own,
  so a credential on a `#` line inside a multi-line quoted value was neither
  reported as a comment nor scanned. The scan now skips only the exact lines
  the whole-file comment report names.
