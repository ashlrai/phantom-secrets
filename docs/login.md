# phantom login — Phantom Cloud Authentication

`phantom login` authenticates your machine with Phantom Cloud using a device
authorization flow. After login, you can push and pull encrypted personal-vault
snapshots on the machine that holds their OS-keychain encryption key. Login does
not transfer or recover that key. Team vault sharing is a separate fixed-membership
workflow that encrypts a shared vault key to registered members.

---

## Device flow

```bash
phantom login
```

1. Phantom opens `phm.dev` in your browser (or prints the URL if it cannot open automatically).
2. A short confirmation code is displayed in the terminal — enter it on the page.
3. Phantom polls for approval in the background with a progress spinner.
4. Once you approve in the browser, the access token is stored in the OS keychain.

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

If already logged in, `phantom login` confirms your identity and exits without re-authenticating:

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

---

## Using cloud sync after login

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

From an MCP-connected AI client, you can trigger these with `phantom_cloud_push` and `phantom_cloud_pull` (both require `confirm: true`).

---

## Reference

- Getting started: [getting-started.md](./getting-started.md)
- Deploy platform sync (Vercel, Railway): [sync.md](./sync.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- Site: [https://phm.dev](https://phm.dev)
