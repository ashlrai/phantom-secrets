# Model-blind agent secrets: decomposition into child jobs

Status: decomposition note. This document is the job graph for the
`RQ-PLAN-SECRETS` epic. It changes no shipping code; the embedded job spec is
validated by `scripts/check-agent-secrets-plan.mjs` (covered by
`scripts/agent-secrets-plan.test.mjs`) so the plan fails loudly when the tree
drifts from it.

Facts verified on 2026-10-26 against `main` at `3d062e9` and the
`codex-bridge/RQ-PS-*` sibling branches already dispatched from this epic.

## 1. Epic

Give a supported AI agent a complete secrets workflow — **create** a secret,
**get** it, and **use** it — plus a first-class **github_api** proxy route —
while keeping the model strictly value-blind: no secret value ever enters tool
arguments, tool results, logs, or any file the agent can read.

### Security invariants (every child job must hold these)

1. MCP tool arguments and results are model context. No tool may accept or
   return a secret value; creation paths either generate inside the process or
   hand the value read to a trusted terminal.
2. Refusals are value-blind too: error strings never echo a stored or supplied
   value.
3. Use means proxy injection only: the local proxy injects the route-owned
   vault value into the matched route's fixed auth header. Client headers and
   bodies never resolve `phm_` mappings.
4. Read paths that need no value never open the vault for retrieval; a locked
   vault degrades to `Vault locked: ...`, never to plaintext fallback.
5. Every new surface ships with a canary test proving the value stays off
   agent-visible output (stdout, stderr, files, MCP transcripts).

## 2. Current state on `main`

| Leg | Surface today | Gap |
|-----|---------------|-----|
| create | `phantom add NAME` hidden prompt / `--stdin` pipe (`crates/phantom-cli/src/commands/add.rs`); MCP `phantom_add_secret_interactive` returns the terminal command (`crates/phantom-mcp/src/server.rs`); `phantom_add_secret` hard-refuses plaintext | An agent cannot *cause* a secret to exist without a human terminal; there is no server-side generate path and no request-fulfill protocol |
| get | `phantom_list_secrets`, `phantom_status`, `phantom_why`, `phantom_list_with_expiry` over MCP; `phantom list/status/why` CLI | No per-secret, value-free metadata read (mapping target, lifecycle, expiry, rotation state). `phantom reveal` exists but needs an attached-terminal typed challenge |
| use | `phantom exec` exports `<SECRET>_BASE_URL` (e.g. `GITHUB_TOKEN_BASE_URL`) and per-route placeholders; the proxy injects only into the matched route's fixed auth header | No end-to-end, value-blind proof suite that a real agent run cannot leak the value |
| github_api | Trusted built-in route `github_api`: secret `GITHUB_TOKEN`, pattern `api.github.com`, `Authorization: Bearer {secret}` (`crates/phantom-core/src/config.rs`); path mapping tested in `crates/phantom-proxy/src/services.rs`; init auto-maps `GITHUB_TOKEN` (`crates/phantom-cli/src/commands/init/config.rs`) | No user-facing docs page, no `phantom exec` level test, no worked example for GitHub API access through the proxy |

`phantom grant add github-app` (manifest flow in
`crates/phantom-core/src/issuance/github_app.rs`) is a related but separate
surface: live provider issuance/rotation stays hard-denied in 0.7.9 and is out
of scope here.

## 3. Child jobs

Jobs are ordered by dependency, not priority. `dispatched` means a
`codex-bridge/<id>` branch already carries a draft; `proposed` means this plan
is the dispatch record.

### C1 `RQ-PS-AGENT-CREATE` — model-blind create (generated values)

Server-side generation so an agent can create a real secret with no value in
context: `phantom add NAME --generate [--bytes N]` and MCP
`phantom_add_secret_generate` draw a CSPRNG value inside the process, store it
in the vault, write the `phm_` mapping, and return only the name and mapping.
Dispatched: `codex-bridge/RQ-PS-AGENT-CREATE`.

### C2 `RQ-PS-AGENT-REQUEST` — model-blind create (human-fulfilled requests)

The complementary create leg for credentials that cannot be generated: the
agent files a value-free request record (`phantom secrets request`), a human
fulfills it in a trusted terminal (`phantom add`), and the agent polls status.
Dispatched: `codex-bridge/RQ-PS-AGENT-REQUEST`.

### C3 `RQ-PS-AGENT-GET` — value-free get

A dedicated metadata read so an agent can resolve a handle without listing
everything or touching a value: `phantom_core::secret_metadata`, MCP
`phantom_get_secret` (name, service mapping, lifecycle/expiry, last-rotation —
never the value), and a CLI `--json` path. Dispatched:
`codex-bridge/RQ-PS-AGENT-GET`.

### C4 `RQ-PS-AGENT-RUN-NOVALUE` — model-blind use (proof harness)

Shared `crates/test-utils` leak-canary helpers plus end-to-end suites that run
the real `phantom` CLI and `phantom-mcp` stdio server in an isolated HOME and
assert a runtime canary never appears on any agent-visible surface. This job
absorbs the C1–C3 verbs as they land, so its *full* acceptance depends on them.
Dispatched: `codex-bridge/RQ-PS-AGENT-RUN-NOVALUE`.

### C5 `RQ-PS-GH-CLIENT` — the github_api route end-to-end

User-facing proof that the route works under `phantom exec`: a boxed runner
example, exec-level tests asserting `GITHUB_TOKEN` is injected into
`Authorization: Bearer` only for `api.github.com`, and docs. Dispatched:
`codex-bridge/RQ-PS-GH-CLIENT`.

### Enabling jobs (already dispatched siblings the epic leans on)

- `RQ-PS-AGENT-ROTATE` — agent-safe remap/rotate that keeps use-legs valid.
- `RQ-PS-AGENT-AUDIT` — usage-audit events for agent-secret operations.
- `RQ-PS-MCP-NOVALUE-AUDIT` — value-blind proofs over the MCP tool catalog.
- `RQ-PS-GITCRED` — `git credential` helper: the second github use-leg
  (git-over-HTTPS auth without a value on disk).
- `RQ-PS-EXEC-API` / `RQ-PS-EXEC-SCRUB` / `RQ-PS-EXEC-COVERAGE` /
  `RQ-PS-EXEC-JSON-SCHEMA` — exec-surface hardening: response scrubbing,
  refusal of unsupported credential flows, machine-readable exec output.

## 4. Job spec

Single source of truth for the graph. `covers` tags the epic legs each job
satisfies (`create`, `get`, `use`, `github_api_route`, plus `audit`,
`rotation`, `hygiene` for enablers). `depends_on` means "must land before this
job's full acceptance can be verified". `claims` pins the main-branch facts
this plan was written against; `present` claims must hold, `absent` claims are
expected to flip when the owning job lands (update the spec in the same PR).

```json phantom-jobspec
{
  "schemaVersion": 1,
  "epic": "RQ-PLAN-SECRETS",
  "verifiedAgainst": { "branch": "main", "commit": "3d062e9", "date": "2026-10-26" },
  "requiredCoverage": ["create", "get", "use", "github_api_route"],
  "coverVocabulary": ["create", "get", "use", "github_api_route", "audit", "rotation", "hygiene"],
  "jobs": [
    {
      "id": "RQ-PS-AGENT-CREATE",
      "title": "Model-blind secret create via server-side generation",
      "covers": ["create"],
      "role": "core",
      "status": "dispatched",
      "branch": "codex-bridge/RQ-PS-AGENT-CREATE",
      "depends_on": [],
      "scope": "phantom add NAME --generate plus MCP phantom_add_secret_generate: CSPRNG value stored in the vault, phm_ mapping written, only name and mapping returned.",
      "surfaces": {
        "new": ["crates/phantom-mcp/src/tools/generate.rs", "crates/phantom-cli/tests/add_generate_test.rs", "docs/generated-secrets.md"],
        "modified": ["crates/phantom-mcp/src/server.rs", "crates/phantom-mcp/src/tools/mod.rs", "crates/phantom-mcp/src/tools/params.rs", "crates/phantom-cli/src/commands/add.rs", "crates/phantom-cli/src/main.rs"]
      },
      "acceptance": [
        "MCP tool returns name + phm_ mapping and never the value; denial strings stay value-free",
        "phantom add --generate refuses to overwrite an existing name before any value work",
        "Generated value lands in the vault and .env gains only the phm_ mapping",
        "mcp-registry/server.json stays in exact lockstep with tools/list"
      ],
      "tests": ["crates/phantom-cli/tests/add_generate_test.rs", "phantom-mcp unit tests in server.rs"],
      "claims": [
        { "expect": "absent", "path": "crates/phantom-mcp/src/tools/generate.rs" },
        { "expect": "absent", "path": "docs/generated-secrets.md" },
        { "expect": "present", "path": "crates/phantom-mcp/src/server.rs", "contains": "phantom_add_secret_interactive" },
        { "expect": "present", "path": "crates/phantom-cli/src/commands/add.rs", "contains": "fn read_secret_value" }
      ]
    },
    {
      "id": "RQ-PS-AGENT-REQUEST",
      "title": "Human-fulfilled secret request protocol",
      "covers": ["create"],
      "role": "core",
      "status": "dispatched",
      "branch": "codex-bridge/RQ-PS-AGENT-REQUEST",
      "depends_on": [],
      "scope": "Value-free request records an agent files and polls; a trusted-terminal fulfill path that reuses phantom add; requests carry names and intended service routes, never values.",
      "surfaces": {
        "new": ["crates/phantom-cli/src/commands/requests.rs", "crates/phantom-cli/tests/secret_requests_test.rs", "docs/secret-requests.md"],
        "modified": ["crates/phantom-cli/src/commands/mod.rs", "crates/phantom-cli/src/main.rs", "crates/phantom-core/src/config.rs"]
      },
      "acceptance": [
        "Request records hold no value field anywhere on disk",
        "Fulfill is trusted-terminal only and refuses non-interactive value entry",
        "Agent-side status polling is value-free end to end"
      ],
      "tests": ["crates/phantom-cli/tests/secret_requests_test.rs"],
      "claims": [
        { "expect": "absent", "path": "crates/phantom-cli/src/commands/requests.rs" },
        { "expect": "absent", "path": "docs/secret-requests.md" }
      ]
    },
    {
      "id": "RQ-PS-AGENT-GET",
      "title": "Value-free per-secret metadata get",
      "covers": ["get"],
      "role": "core",
      "status": "dispatched",
      "branch": "codex-bridge/RQ-PS-AGENT-GET",
      "depends_on": [],
      "scope": "phantom_core::secret_metadata plus MCP phantom_get_secret and a CLI JSON read: name, service mapping, lifecycle/expiry and rotation metadata without opening the vault for retrieval.",
      "surfaces": {
        "new": ["crates/phantom-core/src/secret_metadata.rs", "crates/phantom-cli/tests/get_metadata_test.rs", "docs/agent-safe-get.md"],
        "modified": ["crates/phantom-core/src/lib.rs", "crates/phantom-mcp/src/server.rs", "crates/phantom-mcp/src/tools/mod.rs", "crates/phantom-mcp/src/tools/params.rs", "crates/phantom-cli/src/commands/status.rs", "crates/phantom-cli/src/commands/reveal.rs", "crates/phantom-cli/src/main.rs"]
      },
      "acceptance": [
        "Get returns metadata only; a locked vault degrades to Vault locked, never plaintext",
        "Unknown names answer value-free and point at phantom_list_secrets",
        "mcp-registry/server.json stays in exact lockstep with tools/list"
      ],
      "tests": ["crates/phantom-cli/tests/get_metadata_test.rs", "phantom-core secret_metadata unit tests"],
      "claims": [
        { "expect": "absent", "path": "crates/phantom-core/src/secret_metadata.rs" },
        { "expect": "absent", "path": "docs/agent-safe-get.md" }
      ]
    },
    {
      "id": "RQ-PS-AGENT-RUN-NOVALUE",
      "title": "End-to-end value-blind proof harness",
      "covers": ["use"],
      "role": "core",
      "status": "dispatched",
      "branch": "codex-bridge/RQ-PS-AGENT-RUN-NOVALUE",
      "depends_on": ["RQ-PS-AGENT-CREATE", "RQ-PS-AGENT-GET"],
      "scope": "Shared crates/test-utils canary + JSON-RPC helpers; suites run the real phantom CLI and phantom-mcp in an isolated HOME and assert canaries never surface. Depends on C1/C3 only for full acceptance: scaffolding can land first.",
      "surfaces": {
        "new": ["crates/test-utils/agent_secret.rs", "crates/test-utils/agent_rpc.rs", "crates/phantom-cli/tests/agent_secret_novalue_test.rs", "crates/phantom-mcp/tests/agent_secret_novalue_test.rs"],
        "modified": []
      },
      "acceptance": [
        "Canary never appears on stdout, stderr, files, or MCP transcripts, in plaintext, hex, or base64",
        "Suites exercise create, get, and use legs against real binaries with no mocked vault",
        "Denial paths are asserted value-free, not just success paths"
      ],
      "tests": ["crates/phantom-cli/tests/agent_secret_novalue_test.rs", "crates/phantom-mcp/tests/agent_secret_novalue_test.rs"],
      "claims": [
        { "expect": "absent", "path": "crates/test-utils/agent_secret.rs" },
        { "expect": "absent", "path": "crates/test-utils/agent_rpc.rs" }
      ]
    },
    {
      "id": "RQ-PS-GH-CLIENT",
      "title": "github_api route end-to-end under phantom exec",
      "covers": ["use", "github_api_route"],
      "role": "core",
      "status": "dispatched",
      "branch": "codex-bridge/RQ-PS-GH-CLIENT",
      "depends_on": [],
      "scope": "Docs, a boxed-runner example, and exec-level tests proving GITHUB_TOKEN is injected into Authorization: Bearer only for api.github.com while request bodies stay unresolved.",
      "surfaces": {
        "new": ["docs/github-box-runners.md", "examples/github-box-runner/github.sh", "examples/github-box-runner/test_github.py", "crates/phantom-cli/tests/github_box_example_test.rs"],
        "modified": ["docs/README.md", "examples/README.md"]
      },
      "acceptance": [
        "Exec-level test shows Bearer injection to api.github.com only; non-matching routes get nothing",
        "Example runner works against the real route table and stays value-free",
        "docs/README.md indexes the new page"
      ],
      "tests": ["crates/phantom-cli/tests/github_box_example_test.rs", "examples/github-box-runner/test_github.py"],
      "claims": [
        { "expect": "present", "path": "crates/phantom-core/src/config.rs", "contains": "github_api" },
        { "expect": "present", "path": "crates/phantom-core/src/config.rs", "contains": "api.github.com" },
        { "expect": "present", "path": "crates/phantom-proxy/src/services.rs", "contains": "GITHUB_TOKEN_BASE_URL" },
        { "expect": "present", "path": "crates/phantom-cli/src/commands/init/config.rs", "contains": "apply_detected_services" },
        { "expect": "absent", "path": "docs/github-box-runners.md" },
        { "expect": "absent", "path": "examples/github-box-runner/github.sh" }
      ]
    },
    {
      "id": "RQ-PS-AGENT-ROTATE",
      "title": "Agent-safe rotate for created secrets",
      "covers": ["rotation"],
      "role": "enabler",
      "status": "dispatched",
      "branch": "codex-bridge/RQ-PS-AGENT-ROTATE",
      "depends_on": ["RQ-PS-AGENT-CREATE"],
      "scope": "Value-free rotation metadata and local phm_ remapping that keeps a created secret usable without exposing old or new values; live provider rotation stays hard-denied.",
      "surfaces": {
        "new": ["docs/agent-safe-rotate.md", "crates/phantom-cli/tests/rotate_generate_test.rs"],
        "modified": ["crates/phantom-cli/src/commands/rotate.rs", "crates/phantom-cli/src/commands/exec.rs", "crates/phantom-mcp/src/server.rs", "crates/phantom-mcp/src/tools/params.rs", "crates/phantom-vault/src/file.rs", "crates/phantom-vault/src/traits.rs", "mcp-registry/server.json"]
      },
      "acceptance": [
        "Rotation metadata and remapping never surface a value",
        "Deprecated candidate/promote tools remain hard denials"
      ],
      "tests": ["crates/phantom-cli/tests/rotate_generate_test.rs"],
      "claims": [
        { "expect": "absent", "path": "docs/agent-safe-rotate.md" }
      ]
    },
    {
      "id": "RQ-PS-AGENT-AUDIT",
      "title": "Usage audit for agent-secret operations",
      "covers": ["audit"],
      "role": "enabler",
      "status": "dispatched",
      "branch": "codex-bridge/RQ-PS-AGENT-AUDIT",
      "depends_on": [],
      "scope": "HMAC-chained audit events for agent-driven create/get/use, recording names and operations, never values.",
      "surfaces": {
        "new": ["docs/agent-usage-audit.md", "crates/phantom-vault/tests/agent_usage_audit.rs", "crates/phantom-proxy/tests/usage_audit_refusal_test.rs"],
        "modified": ["crates/phantom-core/src/audit.rs", "crates/phantom-mcp/src/lib.rs", "crates/phantom-mcp/src/server.rs", "crates/phantom-proxy/src/server.rs", "crates/phantom-vault/src/file.rs", "crates/phantom-vault/src/keychain.rs"]
      },
      "acceptance": [
        "Audit schema records names and ops only; chain integrity stays verifiable",
        "Audit-required mode fails closed when the log cannot be written"
      ],
      "tests": ["crates/phantom-vault/tests/agent_usage_audit.rs", "crates/phantom-proxy/tests/usage_audit_refusal_test.rs"],
      "claims": [
        { "expect": "absent", "path": "docs/agent-usage-audit.md" }
      ]
    },
    {
      "id": "RQ-PS-MCP-NOVALUE-AUDIT",
      "title": "Value-blind MCP catalog proofs",
      "covers": ["audit"],
      "role": "enabler",
      "status": "dispatched",
      "branch": "codex-bridge/RQ-PS-MCP-NOVALUE-AUDIT",
      "depends_on": [],
      "scope": "Catalog-level tests proving every agent-callable tool's description, parameters, and denial strings stay value-free.",
      "surfaces": {
        "new": ["crates/phantom-mcp/tests/value_blind_catalog.rs"],
        "modified": ["crates/phantom-mcp/src/server.rs", "crates/phantom-mcp/src/tools/helpers.rs", "crates/phantom-cli/src/commands/mcp_approve.rs"]
      },
      "acceptance": [
        "tools/list descriptions never instruct an agent to supply a value",
        "Approval-gated tools keep the out-of-band nonce contract"
      ],
      "tests": ["crates/phantom-mcp/tests/value_blind_catalog.rs"],
      "claims": [
        { "expect": "absent", "path": "crates/phantom-mcp/tests/value_blind_catalog.rs" }
      ]
    },
    {
      "id": "RQ-PS-GITCRED",
      "title": "git credential helper as a second github use-leg",
      "covers": ["use", "github_api_route"],
      "role": "enabler",
      "status": "dispatched",
      "branch": "codex-bridge/RQ-PS-GITCRED",
      "depends_on": [],
      "scope": "phantom git-credential helper feeding git-over-HTTPS auth from the vault with no token on disk.",
      "surfaces": {
        "new": ["crates/phantom-cli/src/commands/git_credential.rs", "crates/phantom-cli/tests/git_credential_test.rs", "docs/git-credential.md"],
        "modified": ["crates/phantom-cli/src/commands/mod.rs", "crates/phantom-cli/src/main.rs", "README.md"]
      },
      "acceptance": [
        "credential fill never writes the value to disk or stdout beyond the git-helper protocol",
        "erase/store paths refuse or no-op safely"
      ],
      "tests": ["crates/phantom-cli/tests/git_credential_test.rs"],
      "claims": [
        { "expect": "absent", "path": "crates/phantom-cli/src/commands/git_credential.rs" }
      ]
    }
  ]
}
```

## 5. Ordering and dispatch guidance

Wave 1 (independent, all dispatched): C1 create-generate, C2 request, C3 get,
C5 github_api client — each stands alone against today's tree. Wave 2: C4
run-novalue absorbs C1–C3 for full acceptance; enablers (rotate, audits,
git-cred, exec hardening) can interleave freely but should re-run the C4 suite
before landing. Nothing here unblocks live provider issuance — that stays
hard-denied until a separately reviewed design lands.

## 6. Non-goals

- Live provider issuance/rotation (github-app token minting, provider APIs).
- Changing `phantom reveal`'s trusted-terminal contract.
- New service routes beyond github_api (posthog_fleet landed separately in
  `d5f6400`); the route table pattern there is the template for any future one.
