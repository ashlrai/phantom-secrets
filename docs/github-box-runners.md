# GitHub curl client for box runners

Use [the example](../examples/github-box-runner/github.sh) when a box runner
needs to list pull requests, update a branch, or enable GitHub auto-merge.
Requires Bash, curl, jq, and an installed Phantom with the built-in
`GITHUB_TOKEN` → `github_api` route. This is a client recipe, not GitHub App
issuance, Locus activation, or a publication workflow.

An operator first stores `GITHUB_TOKEN` using `phantom add GITHUB_TOKEN` in a
trusted terminal outside agent authority. Never paste the credential into chat,
source, command arguments, or a runner log. Provision the vault and unlock it
through the runner's approved Phantom setup. Obtain tool and repository action
authority through Locus separately; Phantom protects credential delivery and
does not grant permission to update or merge a PR. If Locus is unavailable,
stop before live operations.

From the initialized project root, with the example checked out locally:

```bash
phantom why GITHUB_TOKEN
phantom exec -- bash examples/github-box-runner/github.sh OWNER/REPO list
phantom exec -- bash examples/github-box-runner/github.sh OWNER/REPO list 2
# Replace 42 and the SHA with the exact reviewed PR and its current head SHA.
phantom exec -- bash examples/github-box-runner/github.sh OWNER/REPO update-branch 42 0123456789abcdef0123456789abcdef01234567
# After the asynchronous branch update and review of the new head/checks:
phantom exec -- bash examples/github-box-runner/github.sh OWNER/REPO auto-merge 42 SQUASH
```

The script reads `${GITHUB_TOKEN_BASE_URL}` inside the child; expanding it in
the parent shell loses Phantom's override. It accepts only the loopback
`github_api` route. Phantom injects the route-owned vault value into GitHub's
fixed auth header. No client `Authorization: Bearer $GITHUB_TOKEN` is needed:
child placeholders do not resolve in headers or bodies. Both path-token and
header-only Phantom sessions work. The session URL and `PHANTOM_PROXY_TOKEN`
are sensitive; never print them, use `set -x`, curl verbose/trace, or upload
runner environments. The script supplies these to curl through stdin, disables
curlrc and ambient proxies, and does not follow redirects or retry mutations.

Listing returns one page of up to 100 open PRs; request subsequent pages until
an empty array. Output includes PR numbers, titles, states, and head SHAs, so
keep it within the repository's authorized audience. Update-branch sends
`expected_head_sha` to reject a concurrent head change. Acceptance is
asynchronous, not proof of a completed update. Auto-merge looks up the PR's
GraphQL node ID and checks GraphQL errors even on HTTP 200. It can merge as
soon as GitHub requirements are met; authorize that effect before running it.
It does not pin a reviewed head, bypass protections, or approve a PR.

Use repository-scoped least privilege: listing needs pull-request read access;
branch updates need pull-request write access (GitHub Apps also need contents
write on the head repository). Auto-merge requires merge authority, repository
auto-merge enabled, and an allowed merge method. Follow the current
[REST pull request documentation](https://docs.github.com/en/rest/pulls/pulls#update-a-pull-request-branch)
and [GraphQL mutation documentation](https://docs.github.com/en/graphql/reference/mutations#enablepullrequestautomerge)
for token-specific permissions and policy. Failures such as 401, 403, 422,
rate limits, and transport timeouts return nonzero without dumping provider
responses. For 401, inspect `phantom why GITHUB_TOKEN`; `no_route` means no
credential injection. A timeout on a mutation has an uncertain outcome: inspect
GitHub state through an authorized read before deciding whether to retry.

Offline validation (no vault, real credential, or provider access):

```bash
python3 examples/github-box-runner/test_github.py
shellcheck examples/github-box-runner/github.sh
cargo test --workspace
```

The workspace test invokes the offline example tests on Unix. Python 3 and jq
must be installed. No `publish.sh` is supplied or invoked: publication belongs
to the separately authorized repository workflow.
