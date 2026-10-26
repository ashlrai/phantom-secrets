# Phantom Secrets leak-rate harness

Reproduce: `python3 harness.py 5` (about 3 minutes; needs `phantom` 0.7.9 on PATH, Node, Python 3, git; no paid keys, no network beyond phantom's first-run binary download inside a throwaway HOME).

## What it is (and is not)
A scripted worst-case adversary, not an LLM. For each of 5 runs it generates fresh canary keys (sk-proj-CANARY..., sk_live_CANARY..., sk-ant-api03-CANARY...), builds two throwaway projects in temp dirs with a throwaway HOME, and runs 30 attack techniques x 3 secrets = 90 in-boundary attacks per run:
cat .env, grep -r, printenv, env, /proc/self/environ, python and node env, python open(.env), base64 and hex dumps, git add -f + diff, git log -p, a pattern hunt across project and HOME, ps eww, `phantom reveal` (no TTY and clipboard), export, list, why, status --json, env, doctor, audit, `phantom exec -- env/echo/cat/proc`, calling EVERY MCP tool (54) with confirm=true, and a README prompt-injection that the scripted agent obeys.
- **baseline**: .env holds the real canaries and the dev shell has them loaded.
- **protected**: same project after `phantom init`; shell env holds what `.env` now holds (placeholders).
A leak = the canary appears in anything the attack could see (stdout, stderr, MCP responses, files written), in plain, reversed, base64, hex or URL-encoded form, or as any 16+ character substring (also decoding base64 and hex runs).
2 out-of-scope attacks per run (reading an unmanaged key file the dev never put in .env, grepping HOME for vault contents) are reported separately and never in the headline.

## Honest limits
- Scripted, so it measures where a key CAN appear, not how often a real LLM chooses to go looking.
- A same-user process that can reach the OS keychain or vault is outside Phantom's documented boundary and is not tested as an in-boundary attack.
- "Use is not disclosure": the harness does not test whether an agent can make the proxy use the key against an allowed route (that is by design).
- Linux only, one machine, phantom 0.7.9. No external audit.
- Techniques that do not apply at baseline (the phantom CLI ones) trivially show 0 leaks in both columns.
