# phantom login — Phantom Cloud Authentication

`phantom login` authenticates your machine with Phantom Cloud using a device
authorization flow. After login, you can push and pull encrypted personal-vault
snapshots on the machine that holds their OS-keychain encryption key. Login does
not transfer or recover that key. Team vault sharing is a separate fixed-membership
workflow that encrypts a shared vault key to registered members.

The CLI and protocol are source-backed, but the public hosted service is not
currently commissioned for authenticated use. The commands below describe the
intended operator flow after a deployment and account entitlement have been
independently verified; they are not a claim that `phm.dev` can complete it now.

Login requires attached stdin, stdout, and stderr. Phantom first shows a
value-blind provider-access plan and requires its fresh typed challenge. Before
opening the browser, polling the provider, or storing a keychain token, it shows
the second exact effect plan and requires another fresh typed challenge. An
agent-controlled shell or PTY is not an independent approval channel.

---

## Device flow

```bash
phantom login
```

1. Review and type the first terminal challenge before Phantom reads existing
   cloud credentials or contacts the provider.
2. Review and type the second challenge before browser, polling, and keychain effects.
3. With a commissioned service, Phantom opens `phm.dev` in your browser (or
   prints the URL if it cannot open automatically).
4. A short confirmation code is displayed in the terminal — enter it on the page.
5. Phantom polls for approval in the foreground.
6. Once you approve in the browser, the access token is stored in the OS keychain.

```
->  Open https://phm.dev/device and enter code:

   ABCD-1234

Waiting for approval...
ok  Logged in as @yourname (free)
```

The device code shown in the terminal is not a secret. It expires after a short window (shown during the flow). If it expires before you act, re-run `phantom login`.

---

## Token storage

The access token is stored in the OS keychain under the service name `phantom-cloud`. On macOS this is Keychain Access. On Linux it is the Secret Service (GNOME Keyring or KWallet).

The token is never written to disk, never included in `.phantom.toml`, and never committed to version control.

---

## Checking login status

```bash
phantom status
```

The status output includes your login state, plan tier, and the last cloud sync version if one exists.

Even when a token already exists, `phantom login` requires its initial terminal
challenge before checking that identity with the provider. It then exits without
starting a new device flow:

```
ok  Already logged in as @yourname (free)
```

---

## Logging out

```bash
phantom logout
```

This deletes the access token from the OS keychain. It does not delete your vault
data on Phantom Cloud. The cloud copy remains ciphertext and can be restored only
where the original machine-local cloud encryption key remains available.
Logout also requires attached stdin, stdout, and stderr plus the exact typed
challenge before the keychain token is deleted.

---

## Using cloud sync after a verified hosted commissioning

Push the local vault to Phantom Cloud:

```bash
phantom cloud push
```

Pull a personal-vault snapshot from Phantom Cloud on the machine that holds the
original cloud encryption key:

```bash
phantom cloud pull
```

Both commands require an active login and access to the original OS-keychain
encryption key. Phantom Cloud stores only ciphertext. Phantom does not currently
ship personal cloud-key export, transfer, or recovery, so this path is a
same-keychain-machine backup rather than cross-machine sync.

Each command also requires attached stdin, stdout, and stderr plus its own exact
typed challenge before credential access or network/mutation effects. A
non-forced pull that skips any existing local secret retains the prior merge
base, records a durable reconciliation requirement, and blocks a later push
until a full pull is applied. `--force` declares overwrites; it does not bypass
the ceremony.

From an MCP-connected AI client, `phantom_cloud_push` and
`phantom_cloud_pull` both require `confirm: true` plus a one-use
`approval_token` created through the out-of-band `phantom mcp-approve`
terminal ceremony. Keep that approval command outside the agent's authority.

---

## Reference

- Getting started: [getting-started.md](./getting-started.md)
- Deploy platform sync (Vercel, Railway): [sync.md](./sync.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- Site: [https://phm.dev](https://phm.dev)
