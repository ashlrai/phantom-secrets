# `phantom exec` CLI coverage

`phantom exec` gives its child fresh placeholders and starts an authenticated
loopback reverse proxy. A supported request must reach an approved route on
that proxy. The route injects its own vault credential into its fixed auth
header. A placeholder sent directly to a provider is not a working credential.
Client headers and request bodies never resolve placeholders.

This is endpoint routing, not a system HTTP proxy, TLS interception, or a
network sandbox. Setting `HTTPS_PROXY` to Phantom does not add CLI support.
An exported `*_BASE_URL` only helps software that actually reads that variable
and preserves the route path.

## Coverage inventory

| CLI / operation | Coverage with managed placeholders | Behavior and next step |
| --- | --- | --- |
| `gh` authenticated commands | Unsupported | The built-in `github_api` route serves GitHub REST requests, but `gh` does not consume Phantom's `GITHUB_TOKEN_BASE_URL`. Direct commands with protected GitHub credentials are refused with guidance. Use an explicit routed HTTP request for supported API work. |
| `npm run`, `npm test`, `npm start` and other local script commands | Conditional | Scripts inherit the session placeholders and supported SDK base URLs. They work when the script's client uses those URLs; this does not add support to every program the script launches. |
| `npm` registry authentication, including private installs and publishing | Unsupported | npm scopes authentication to registry URLs through its configuration. Phantom has no approved npm registry adapter; direct registry commands with protected npm or GitHub Packages credentials are conservatively refused. Public operations without those protected credentials are not evidence of private-registry support. |
| `vercel` authenticated commands | Unsupported | Phantom has no approved Vercel CLI route/adapter. Direct commands with protected Vercel credentials are refused. Vercel's own endpoint override does not establish Phantom support. |
| `supabase` authenticated management commands | Unsupported | The CLI's personal access token is distinct from project data API keys. The existing Supabase data API routes do not provide a Management API adapter. Direct commands with protected CLI credentials are refused. Database work also needs a protocol-aware broker; placeholder substitution cannot authenticate a database connection. |
| `aws` signed requests | Unsupported | AWS requests require SigV4/SigV4a signing with credentials. Replacing one static header cannot repair a signature calculated with a placeholder. Direct commands with protected AWS credentials are refused, even with an endpoint override. |
| `curl` to an approved Phantom route | Supported when explicitly addressed | Send the request to the session's route URL, using path authentication or the proxy authentication header as shown below. Ordinary public URLs are not rewritten. |
| `git` HTTPS network operations | Unsupported | Git's credential helpers and smart HTTP transport are separate from the GitHub REST API. Direct network commands with protected GitHub credentials are conservatively refused, including named or SSH remotes whose transport is not inferred. Local Git operations remain available. |

Refusals happen before vault access and child launch when the relevant managed
credential is present. This check exempts standalone help/version and recognized
local command forms; other exec preflights still apply. It recognizes direct
CLI invocations and does not recursively
inspect shell scripts, npm scripts, aliases, or arbitrary executables. Wrapping
an unsupported command in a shell does not make its placeholders work. Existing
CLI login files, credential helpers, and unrelated ambient credentials are not
made value-blind by this coverage check.

The check uses managed dotenv key names, never credential values or CLI login
files: `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN` and
`GITHUB_ENTERPRISE_TOKEN` for gh/Git; those same names plus `NPM_TOKEN`,
`NODE_AUTH_TOKEN` and `NPM_AUTH_TOKEN` for npm; `VERCEL_TOKEN` and
`VERCEL_ACCESS_TOKEN` for Vercel (including `vc`); `SUPABASE_ACCESS_TOKEN` and
`SUPABASE_DB_PASSWORD` for Supabase; and `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` and `AWS_SECURITY_TOKEN` for AWS.
Custom variable names are not inferred from registry or credential-helper
configuration. Bare `vercel` is a deployment command and is refused too.

For npm scripts, put the command first: `npm run build --workspace app`, not
`npm --workspace app run build`. Unknown npm forms remain refused with those
protected credentials. Git's common local forms and remote listing/get-url/
set-url remain available; unknown forms, `remote update`, `remote add` (which
can fetch), and external aliases are refused. Local Git commands can still run
hooks, external diff tools or lazy fetches in partial clones. This check does
not inspect those secondary operations or guarantee that a local command
stays offline. The existing database-credential and route validation gates
still apply, including to help/version invocations.

`phantom why <KEY>` explains the managed key's route delivery. A route existing
for a key does not prove that a particular CLI uses it. In particular,
`GITHUB_TOKEN` can have a valid REST route while direct `gh` remains unsupported.

## Explicit GitHub API requests with curl

These examples assume the project already protects `GITHUB_TOKEN` and has the
approved `github_api` route. Do not paste real credentials into commands or
chat. The child shell expands session variables after `phantom exec` starts;
the single quotes are intentional.

The default path-authenticated base URL includes a sensitive, short-lived proxy
bearer. Append the endpoint to that URL without removing its path:

```sh
phantom exec -- sh -c 'exec curl --fail --silent --show-error "${GITHUB_TOKEN_BASE_URL}user"'
```

For header-only mode, use the route URL and send the separate proxy bearer in
`x-phantom-proxy-token`:

```sh
PHANTOM_PROXY_HEADER_AUTH_ONLY=1 phantom exec -- sh -c 'exec curl --fail --silent --show-error -H "x-phantom-proxy-token: ${PHANTOM_PROXY_TOKEN}" "${GITHUB_TOKEN_BASE_URL}/user"'
```

Neither example needs a provider `Authorization` header: the matched route owns
that header. Keep session URLs and proxy bearers out of logs; do not enable
shell tracing or verbose HTTP output. Do not send the proxy bearer to a public
provider URL. Use API endpoints whose responses are appropriate to display.

## Structured launch errors and output scrubbing

`phantom exec --json -- <command>` leaves stdout to the child. Launch refusals
are one `phantom.exec.error.v1` object on stderr with an `error.code` and a
fixed, value-free `error.message`. Diagnostic paths, arguments, mappings and
underlying error text are excluded. Codes include `unknown_route`,
`placeholder_mismatch`, `missing_secret`, `proxy_not_running`,
`legacy_proxy_running`, `legacy_proxy_unsafe`, `spawn_failed` and the fallback
`exec_failed`. A missing executable still exits 127; a nonexecutable command
still exits 126. Once the child launches, its exit status and output remain
the child's contract rather than becoming a JSON report.

Add `--scrub-output` to scan each child output stream independently for active
managed values and recognized credential formats, including matches split
across reads. It works with `--json` and with direct launches that need no
vaulted credentials. Scrubbing pipes stdout and stderr, which changes terminal
detection and can affect buffering and interactivity. Ordinary bytes are
preserved; candidate prefixes can be delayed until more output or EOF arrives.
Encoded values and arbitrary unknown secrets are outside this redaction scope.

## Verification boundaries

The CLI coverage tests use a loopback mock upstream and synthetic credentials.
They exercise the refusal table, request routing, fixed-header injection, and
credential isolation without contacting providers. Library-level mock requests
prove the proxy contract; they are not certification of installed vendor CLI
versions or successful live provider operations. An npm script's ability to
inherit route variables also does not certify all npm scripts or dependencies.

## Upstream contracts

The inventory distinguishes Phantom's current adapters from the capabilities
of upstream tools:

- [GitHub CLI environment variables](https://cli.github.com/manual/gh_help_environment)
  describe host selection and GitHub token variables.
- [npm registry authentication configuration](https://docs.npmjs.com/cli/v8/configuring-npm/npmrc/)
  scopes credentials to a registry host or path.
- [Vercel CLI options](https://vercel.com/docs/cli/global-options) describe token
  authentication; [the CLI source](https://github.com/vercel/vercel/blob/main/packages/cli/src/index.ts)
  also accepts an API URL override.
- [Supabase personal access tokens](https://supabase.com/docs/guides/platform/personal-access-tokens)
  authenticate Management API commands separately from database passwords.
- [AWS request signing](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
  requires a signature derived from credentials and request details.
- [Git credentials](https://git-scm.com/docs/gitcredentials) describe HTTPS
  authentication and credential helpers.
