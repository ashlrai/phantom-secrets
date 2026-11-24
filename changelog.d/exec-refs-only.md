### Security (`phantom exec --refs-only`)

- New `phantom exec --refs-only`: the session serves only names passed as
  `NAME=secret://NAME`. Other dotenv names are not loaded, get no session
  token or base-URL override, and their proxy routes are refused with no
  injection. Without a reference the launch is refused. Without the flag,
  behavior is unchanged. See `docs/design/builtin-vault.md` section 4.6a.
