# GitHub credential helper

`phantom git-credential` supplies an existing project vault entry to Git's
credential protocol. Configure it locally from the protected project root:

```sh
git config --local credential.https://github.com.helper '!phantom git-credential'
```

The default entry is `GITHUB_TOKEN`. To select another exact vault entry:

```sh
git config --local credential.https://github.com.helper '!phantom git-credential --secret GITHUB_PAT'
```

Provision credentials with `phantom add GITHUB_TOKEN` from a trusted terminal;
never put a token in Git configuration, command arguments, or chat. The helper
uses the current project's vault and applies its rotation and lifecycle gates.
It does not read credentials from the environment or fall back to another store.
Git receives `username=x-access-token` and the vault credential as `password`.
Only `protocol=https` and the exact host `github.com` are accepted; other hosts,
ports, and protocols receive no credential. `store` and `erase` do nothing.

This is an explicit plaintext handoff to Git, outside Phantom's value-blind
proxy boundary. On Unix and Windows, `get` requires stdout to be a pipe: terminals, regular files, sockets,
and devices are refused before the vault is opened. Other platforms fail closed. A pipe check cannot authenticate Git or prevent an arbitrary pipe
reader from capturing the response. Use this helper only in trusted execution;
do not run it directly from an agent or log its output. Other configured Git
helpers may store credentials after successful authentication; review or clear
those helpers if persistence is unwanted. This command never changes Git config.
