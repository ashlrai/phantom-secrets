# GitHub box runner

See [setup, commands, permissions, and failure handling](../../docs/github-box-runners.md).
`github.sh` is a curl client run under `phantom exec --`; `test_github.py`
exercises the script with fake curl and a loopback HTTP server, with no provider
or vault access.
