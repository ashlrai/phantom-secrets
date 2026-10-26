# Benchmarks

Same VM and day as [First run](FIRST-RUN.md): Ubuntu 24.04.5 LTS, Linux
6.12.94+, x86_64, Intel Xeon, 4 CPUs, 2026-10-26. Every secret value stayed in
the harness. Logs record lengths, hashes of those values, and exit codes.

## Method

Each tool got a fresh directory and one API-key-shaped value written into a
file by the harness. The value was not passed on a command line.

1. Install from the upstream the project documents, and verify a published
   checksum when that upstream publishes one.
2. Store or encrypt that one value.
3. Run a child seven times. The child prints whether `SHA-256(OPENAI_API_KEY)`
   matches a digest the harness kept, plus the value length. It does not print
   the value.
4. During a separate `sleep 1.2` (Phantom used `sleep 1.0`), read the parent
   `VmHWM` from `/proc/<pid>/status` and the child RSS from `ps`.

Phantom's child does not receive the vault value. Its check records the
placeholder and the loopback base URL. dotenvx and SOPS are scored by the hash
match. Header injection to `api.openai.com` was not timed, because that would
send the vault value off the machine. `phantom exec` on `v0.7.9` has fixed
provider routes.

## Results

| Tool | Install | Store | Exec median of 7 | Parent VmHWM | What the child received |
|---|---|---|---|---|---|
| Phantom 0.7.9 | 0.706 seconds, checksum verified | `phantom init` 0.013 seconds | 0.0122 seconds (min 0.0112, max 0.0133) | 13088 kB high, 12940 kB on the sample with a visible child | `phm_` session token, length 68, and `OPENAI_BASE_URL` on `127.0.0.1`. Vault value was not in the environment. Parent text: `0 env var(s) injected directly` |
| dotenvx 2.38.2 | 0.933 seconds, checksum verified | `dotenvx encrypt` 0.205 seconds | 0.2113 seconds (min 0.1998, max 0.2179) | 82788 kB. `sleep` child peak 2196 kB | Hash matched. Value length 73 |
| SOPS 3.13.3 plus age 1.3.2 | 0.964 seconds. SOPS checksum verified. age archive was not checksum-verified | `age-keygen` 0.0022 seconds, then `sops --encrypt` 0.0141 seconds | 0.0203 seconds (min 0.0193, max 0.0224) | 34912 kB. `sleep` child peak 1944 kB | Hash matched. Value length 73. `NODE_ENV` stayed `development` |

Phantom exec samples, in order: 0.0122, 0.0132, 0.0125, 0.0119, 0.0117, 0.0133,
0.0112 seconds.

dotenvx exec samples: 0.2033, 0.2125, 0.2113, 0.2024, 0.2179, 0.2116, 0.1998
seconds.

SOPS exec samples: 0.0224, 0.0207, 0.0214, 0.0195, 0.0194, 0.0203, 0.0193
seconds.

Download pieces inside those install times:

| Piece | Bytes | Seconds |
|---|---|---|
| Phantom archive, first fetch | 18342713 | 0.199 |
| Phantom `.sha256` sidecar | 106 | 0.157 |
| Phantom `sha256sum -c` | | 0.015, exit 0 |
| Phantom extract | | 0.307 |
| dotenvx `v2.38.2` `dotenvx-linux-x86_64.tar.gz` | 26311549 | 0.267 |
| dotenvx `checksums.txt` | 2416 | 0.095 |
| SOPS `sops-v3.13.3.linux.amd64` | 52121762 | 0.324 |
| SOPS `sops-v3.13.3.checksums.txt` | 630 | 0.139 |
| age `age-v1.3.2-linux-amd64.tar.gz` | 19405817 | 0.176 |

A second Phantom archive fetch was 0.231 seconds for the same 18342713 bytes.
The README-shaped dotenvx name `dotenvx-Linux-x86_64.tar.gz` from
`releases/latest/download` returned HTTP 200 in 0.344 seconds and the same
SHA-256 as `dotenvx-linux-x86_64.tar.gz`. `sha256sum -c` against `checksums.txt`
succeeded for the lowercase name.

`sops --version` printed `sops 3.13.3 (latest)` and a warning that a future
version will stop checking whether the binary is the latest. A repeat of that
command took 0.053 seconds and 0.051 seconds. That check sits inside the 0.964
second install time. `phantom --version` was 0.003 seconds and made no such
request.

## How each store-and-run was invoked

Phantom, after the README install: `phantom init`, then
`phantom exec -- python3 <checker>`. Details and the agent-CLI audit are in
[First run](FIRST-RUN.md).

dotenvx, from the GitHub release snippet in its README
(`curl` of `dotenvx-$(uname -s)-$(uname -m).tar.gz`, then `tar`, then
`dotenvx encrypt`). The timed install also verified `checksums.txt`, which that
snippet does not. `dotenvx encrypt` rewrote `.env` and wrote `.env.keys`.
`NODE_ENV` was encrypted along with the API key (ciphertext length 154, prefix
`encrypted`). `dotenvx run --quiet -- python3 <checker>` was the exec.

SOPS, from [getsops.io/docs/installation](https://getsops.io/docs/installation/),
which points at the GitHub release binaries. age came from the `v1.3.2` Linux
amd64 archive. The release publishes `age-v1.3.2-linux-amd64.tar.gz.proof` and
no `.sha256` sidecar, and the proof was not checked. Encrypt command:
`sops --encrypt --age <public key> --input-type dotenv --output-type dotenv`.
The ciphertext did not contain the plaintext. Exec command that succeeded:
`sops exec-env <file> "python3 <checker>"` with `SOPS_AGE_KEY_FILE` set.
`sops exec-env <file> python3 <checker>` exited 1 with
`error: missing file to decrypt`. In the `v3.13.3` source,
`cmd/sops/main.go` requires `c.NArg() == 2`, so the command has to be one
argument. The error text still says the file is missing.

## Feature gaps

Phantom has a local proxy, `phm_` placeholders, value-blind `list --json`, and
an MCP `tools/list` of 54 names that matched `mcp-registry/server.json` on this
tree. dotenvx and SOPS inject the stored value into an arbitrary child. Phantom
`v0.7.9` does not. A connection string stored by Phantom makes `phantom exec`
refuse to start. That is the gap for database commands and for any program that
reads the key from the environment.

dotenvx encrypts every value it writes, including `NODE_ENV`. Phantom left
`NODE_ENV` and `PORT` as plaintext. dotenvx's documented `dotenvx set HELLO World`
takes the value as an argument. Phantom `add` rejects a positional value and
accepts `--stdin` without a TTY (measured exit 0).

Phantom's local exec median on this VM is 0.0122 seconds. SOPS `exec-env` is
0.0203 seconds, and that run does put the plaintext in the child. The parent
RSS for that successful SOPS run was 34912 kB against Phantom's 13088 kB.
dotenvx's parent was 82788 kB and its exec median was 0.2113 seconds.

SOPS and age need a key file on disk for this flow. Phantom's measured backend
was the kernel keyring, which its own line labels volatile across reboot.
dotenvx keeps a private key in `.env.keys`.

## Tools not timed

Infisical CLI (`https://github.com/Infisical/cli`, README read 2026-10-26)
describes injection and says authentication is with Infisical Cloud or a
self-hosted instance. A first `infisical run` on an empty VM needs that
service, so it is a different job from the three standalone installs above.

1Password CLI `op run` is the usual account-backed injection command
(`https://developer.1password.com/docs/cli/get-started/`). A request for
`https://github.com/1Password/op` on 2026-10-26 returned HTTP 404. It was not
installed here.

## Sources

- Phantom `v0.7.9` assets: `https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.9`
- Phantom Linux script and the agent audit: [FIRST-RUN.md](FIRST-RUN.md)
- dotenvx README install and `dotenvx encrypt` / `dotenvx run`: `https://github.com/dotenvx/dotenvx` (`BSD-3-Clause`, tag `v2.38.2`)
- dotenvx checksums: `https://github.com/dotenvx/dotenvx/releases/download/v2.38.2/checksums.txt`
- SOPS install: `https://getsops.io/docs/installation/` and release `v3.13.3` (`MPL-2.0`)
- SOPS `exec-env` argument count: `https://github.com/getsops/sops/blob/v3.13.3/cmd/sops/main.go`
- age `v1.3.2`: `https://github.com/FiloSottile/age/releases/tag/v1.3.2` (`BSD-3-Clause`)
