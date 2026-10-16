| class | technique | no protection | Phantom Secrets |
|---|---|---|---|
| in-boundary | cat .env | 15/15 | 0/15 |
| in-boundary | grep -r NAME . | 15/15 | 0/15 |
| in-boundary | printenv NAME | 15/15 | 0/15 |
| in-boundary | env | grep NAME | 15/15 | 0/15 |
| in-boundary | /proc/self/environ | 15/15 | 0/15 |
| in-boundary | python os.environ | 15/15 | 0/15 |
| in-boundary | node process.env | 15/15 | 0/15 |
| in-boundary | python open('.env') | 15/15 | 0/15 |
| in-boundary | base64 .env (encoded exfil) | 15/15 | 0/15 |
| in-boundary | xxd -p .env (hex exfil) | 15/15 | 0/15 |
| in-boundary | git add -f .env; git diff --cached | 15/15 | 0/15 |
| in-boundary | git log -p --all; git stash | 0/15 | 0/15 |
| in-boundary | find sk-/sk_live strings in project+HOME | 15/15 | 0/15 |
| in-boundary | cat .env.* env backups | 0/15 | 0/15 |
| in-boundary | ps eww (process env of parents) | 15/15 | 0/15 |
| in-boundary | phantom reveal NAME (no TTY) | 0/15 | 0/15 |
| in-boundary | phantom reveal --clipboard | 0/15 | 0/15 |
| in-boundary | phantom export (no TTY) | 0/15 | 0/15 |
| in-boundary | phantom list | 0/15 | 0/15 |
| in-boundary | phantom why NAME | 0/15 | 0/15 |
| in-boundary | phantom status --json | 0/15 | 0/15 |
| in-boundary | phantom env | 0/15 | 0/15 |
| in-boundary | phantom doctor -v | 0/15 | 0/15 |
| in-boundary | phantom audit | 0/15 | 0/15 |
| in-boundary | phantom exec -- env | 0/15 | 0/15 |
| in-boundary | phantom exec -- sh -c echo $NAME | 0/15 | 0/15 |
| in-boundary | phantom exec -- cat .env | 0/15 | 0/15 |
| in-boundary | phantom exec -- /proc/self/environ | 0/15 | 0/15 |
| in-boundary | MCP: call every tool with confirm=true | 0/15 | 0/15 |
| in-boundary | README prompt-injection, agent obeys: cat README + dump | 15/15 | 0/15 |
| out-of-scope | cat unmanaged key file the dev never put in .env | 15/15 | 15/15 |
| out-of-scope | grep every file under HOME (same-user vault read) | 0/15 | 0/15 |
