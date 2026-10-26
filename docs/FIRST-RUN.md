# First run

Measured on 2026-10-26 against the published `v0.7.9` Linux binaries. The
steps follow the root README install and quick start. Secret values were
generated in the measurement process and are not recorded here.

Related numbers for dotenvx and SOPS are in [Benchmarks](BENCHMARKS.md).

## Machine

- Ubuntu 24.04.5 LTS, Linux 6.12.94+, x86_64, Intel Xeon, 4 CPUs
- `curl`, `sha256sum`, `tar`, `python3`, `node`, and `bash` were already installed
- `phantom`, Homebrew, and `/usr/bin/time` were not installed
- Each run used a fresh `HOME` and a project directory outside this repository
- GitHub download times are for this VM. Two downloads of the same 18342713 byte archive took 0.199 seconds and 0.231 seconds

## What the README says to do

The Install section leads with Homebrew. For Linux it points at the
[v0.7.9 asset table](../README.md#exact-v079-github-assets): download the
matching archive and its `.sha256` sidecar, run `sha256sum -c`, and place
`phantom` and `phantom-mcp` on `PATH`. The quick start then runs `phantom init`,
`phantom agent doctor`, and `phantom exec -- claude`.

The README does not give a copy-paste Linux script. [Getting started](getting-started.md)
now has the script that was timed below. `scripts/install.sh` in this
repository is a one-command installer, and the root README does not mention it.
The `v0.7.9` GitHub release has 19 assets. `install.sh` is not one of them.

## Timed path

Asset: `phantom-x86_64-unknown-linux-gnu.tar.gz` from
`https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.9/`.

| Stage | Result |
|---|---|
| Archive download | 0.199 seconds, 18342713 bytes, HTTP 200 |
| Sidecar download | 0.157 seconds, 106 bytes, HTTP 200 |
| `sha256sum -c` | exit 0 in 0.015 seconds. The sidecar hash matches the linux x86_64 `sha256` in the ashlrai/homebrew-phantom formula fetched the same day |
| Extract | 0.307 seconds. Archive members are `phantom` and `phantom-mcp` |
| `phantom --version` and `phantom-mcp --version` | `phantom 0.7.9` and `phantom-mcp 0.7.9`. The version command itself was 0.003 seconds |
| Install through both version commands | 0.706 seconds |
| Same steps as one shell script, second download | 0.751 seconds, both version commands printed `0.7.9` |
| `bash scripts/install.sh` in a fresh `HOME` | exit 0 in 1.392 seconds. It installed `0.7.9` under `~/.phantom-secrets/bin` and appended that directory to `~/.bashrc` in that home |

`phantom init` on a new project whose `.env` held one detected API key plus
`NODE_ENV` and `PORT`:

- exit 0 in 0.013 seconds
- backend line: `linux-keyutils (volatile across reboot)`
- `.env` API-key value became a `phm_` token of 68 characters. The init line showed 12 characters of it
- `NODE_ENV` and `PORT` were unchanged
- `.env.example` placeholders did not start with `phm_` or `sk-`
- `.gitignore` lists `.env`, `.env.local`, `.env.*.local`, `.env.backup`, `.phantom.proxy.lock`, `.phantom.pid`, and `.phantom.start.lock`
- `CLAUDE.md` was created

A second `phantom init` in the same directory exited 0 in 0.004 seconds and
left the `.env` bytes unchanged. It reported that no real secrets remained and
that tokens were not rotated.

`phantom exec -q -- python3 <checker>` after that init, seven runs: 0.0122,
0.0132, 0.0125, 0.0119, 0.0117, 0.0133, and 0.0112 seconds. Minimum 0.0112,
median 0.0122, maximum 0.0133. Each run exited 0.

Adding the 0.706 second install, the 0.013 second init, and the 0.0122 second
median exec gives 0.731 seconds from the start of the download to a successful
exec. Writing the project `.env` was a local file write before init and is
outside that sum. That is under the 60 second target. The README path is still
four steps: download, checksum, extract, and copy onto `PATH`.

## What "injected" meant

The checker in the child process reported:

- `OPENAI_API_KEY` started with `phm_` and was 68 characters. It did not start with `sk-`
- `OPENAI_BASE_URL` started with `http://127.0.0.1:` and contained `/_phantom/`
- `PHANTOM_PROXY_PORT` was set and `PHANTOM_PROXY_TOKEN` was 64 characters
- `PHANTOM_VAULT_PASSPHRASE` was absent

The parent printed `1 secret(s) proxied, 0 env var(s) injected directly` and
still printed 11 `*_BASE_URL` assignments (Hugging Face, OpenAI, xAI, Stripe,
Mistral, Perplexity, Gemini, Anthropic, Replicate, Supabase, and Cohere).
`-q` is documented as suppressing output other than errors. On this binary it
did not suppress those lines, and they were on stdout.

The vault value was not sent to a provider. `phantom exec` on this binary
forwards built-in routes to the provider hosts, so a live header check would
have exposed the vault value. The timed command is the local exec that loads
the vault entry into the proxy and starts the child.

While one exec held `sleep 1.0`, the phantom parent `VmHWM` was 12940 kB and
`ps` showed a `sleep` child at 2200 kB RSS. An earlier sample in the same
session reached 13088 kB `VmHWM` for the parent.

`phantom add STRIPE_SECRET_KEY --stdin` with a piped value exited 0. Its stdout
said the value was never printed. `phantom list --json` then named
`OPENAI_API_KEY` and `STRIPE_SECRET_KEY`. The piped value was not present in
`.env`.

## Friction

1. Linux install is not one command in the README. The repository installer works (1.392 seconds here) and is not attached to the `v0.7.9` release.
2. After init, the `v0.7.9` binary's "What's next?" lists `phantom exec`, `phantom doctor`, `phantom login`, `phantom open`, `pre-commit install`, and `phantom setup`. `phantom login` and `phantom open` are hosted flows. `pre-commit install` expects `.pre-commit-hooks.yaml`, which the release archive does not contain. The project was not a git repository, so init did not install a git hook either.
3. The backend name says keyutils is volatile across reboot. The generated `CLAUDE.md` says "Real secrets are in an encrypted vault (OS keychain)". The README quick start does not mention `PHANTOM_VAULT_PASSPHRASE`. After a reboot the kernel keyring is empty and `.env` still holds only tokens.
4. `phantom exec` arms a proxy. It does not place the vault value in the child environment. The quick start line `phantom exec -- claude` needs a `claude` binary this install does not provide.
5. `phantom doctor --json`, `phantom why OPENAI_API_KEY --json`, `phantom check --json`, `phantom agent doctor --json`, and `phantom --json init` all exited 0 and printed human text. `phantom why` included 12 characters of the token. `phantom list --json` and `phantom status --json` did print JSON. `status --json` set `vault.inspected` and `managed_dotenv.inspected` to false.
6. `phantom doctor` passed with `.env has 3 entries, all protected` while two of the three entries were `NODE_ENV` and `PORT`. This tree now says "no unprotected secrets" for that case.
7. `phantom agent doctor` exited 0 with status `Protected`, risk `Medium`, and told the operator to run `phantom init` for a missing pre-commit check after init had already succeeded. It also suggested `phantom login` and `phantom sync --platform vercel`.
8. `phantom setup --status` and `phantom setup --client cursor --dry-run` both exited 2 with `unexpected argument`. The current README command reference documents both flags. They exist in this tree and are absent from the measured binary.
9. `phantom init --dry-run` without `--all` exited 2 and named `--all <DIR>`. `phantom add` with no TTY exited 1 and named `--stdin`. `phantom remove` with no TTY exited 1 and said no value was read and no state changed. `phantom exec` with no command exited 2. `phantom exec -- true` with no `.phantom.toml` exited 1 and named `phantom init`. `phantom init` with no `.env` exited 1 and listed the filenames it checked.

## Already different in this tree

These are source readings, not a second timed build:

- Init next steps lead with `phantom agent doctor`, `phantom setup`, and `phantom exec`. The login, open, and `pre-commit install` lines are gone. Keyutils gets an explicit reboot warning.
- `CLAUDE.md` text for a linux-keyutils backend says the kernel keyring is volatile.
- `phantom doctor --json`, `phantom agent doctor --json`, `phantom why --json`, and `phantom check --json` print JSON. `phantom --json init` is rejected because init has no JSON output.
- Exec progress honors `-q` and is written to stderr. Base URL variables are exported for routes whose credential was loaded.
- `phantom setup --status` and `phantom setup --dry-run` are accepted flags.

## Agent surface on the measured binary

| Check | Result |
|---|---|
| Init with no TTY | exit 0 |
| Init again | exit 0, dotenv bytes unchanged |
| `add` with no TTY and no `--stdin` | exit 1, tells the caller to use `--stdin` or a hidden prompt |
| `add --stdin` | exit 0, name stored, value absent from `.env` |
| `remove` with no TTY | exit 1 before any change |
| `--dry-run` on single-project init | exit 2 unless `--all` is set |
| `--json` on `list` | names and detected service only |
| MCP `tools/list` | 54 names from `phantom-mcp` and from `phantom mcp serve`. The sorted names matched `mcp-registry/server.json` in this tree, including `phantom_list_secrets` and `phantom_do` |

## Ranked follow-ups

1. **Small.** Put the Linux script from Getting started into the root README. `README.md` is already edited by the open 0.8.0 pull request, so this patch leaves it alone.
2. **Medium, release packaging.** Attach `scripts/install.sh` to the GitHub release and point the README at the local file. The script succeeded here in 1.392 seconds. It is not a `v0.7.9` asset, and this patch does not edit release workflows. The 0.8.0 pull request already edits the installer.
3. **Medium.** Add `--dry-run` to single-project `phantom init`, `phantom add`, and `phantom remove`. Today a headless caller can preview `init --all` only. `add` and `remove` are transactions, so the preview has to share their exact plan.
4. **Medium.** Make the first Linux run durable without a separate passphrase step, or refuse to rewrite `.env` until the operator picks keyutils or the encrypted file. The measured backend is wiped on reboot after the plaintext is gone. This tree warns. It still selects keyutils when no passphrase is set.
5. **Large.** Run one non-HTTP command with a vault value without printing that value into an agent transcript. dotenvx and SOPS inject into the child environment. Phantom loads the value into the proxy and refuses protected connection strings. The database broker described in Getting started is that work.
6. **Small, behavior change.** Write `CLAUDE.md` only when a Claude project is already present. Measured init created it in an empty directory. The inaccurate keychain sentence is already corrected in this tree. Skipping the file would change onboarding and needs its own tests.
