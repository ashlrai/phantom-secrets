### Changed (docs: `phantom start` shell exports)

- Troubleshooting now explains what `phantom start` prints for you to run
  (base-URL exports, unset lines for unloaded routes, `PHANTOM_PROXY_PORT`,
  `PHANTOM_PROXY_TOKEN`, `PHANTOM_SESSION_KEYS`) and how it picks bash/zsh,
  fish, PowerShell or cmd.exe syntax, including the previously undocumented
  `PHANTOM_SHELL` override. `docs/llms-full.txt` notes the same.
