# CI/CD Integration

Phantom's current CI support is strongest when secrets are synced into a deployment platform before the build runs. Direct Phantom Cloud pull from headless CI is not supported yet because the CLI does not currently expose a non-interactive cloud login flow.

## GitHub Actions

Use GitHub Actions for checks, builds, and deploy commands, but do not rely on the disabled Phantom GitHub Action for cloud vault pulls.

```yaml
name: Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install the immutable Phantom v0.7.9 Linux release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release download v0.7.9 --repo ashlrai/phantom-secrets \
            --pattern phantom-x86_64-unknown-linux-gnu.tar.gz \
            --pattern phantom-x86_64-unknown-linux-gnu.tar.gz.sha256
          sha256sum -c phantom-x86_64-unknown-linux-gnu.tar.gz.sha256
          tar -xzf phantom-x86_64-unknown-linux-gnu.tar.gz
          install -d "$HOME/.local/bin"
          install -m 0755 phantom phantom-mcp "$HOME/.local/bin/"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: Check for unprotected secrets
        run: phantom check

      - name: Build
        run: npm ci && npm run build
```

The repository action at `integrations/github-actions/action.yml` is a fail-fast placeholder until a supported non-interactive Phantom Cloud auth flow exists.
The example downloads immutable `v0.7.9`, whose tag resolves to source commit
`7a51ce512ec4aee12cc29ff859036af63fbe93db`, and verifies its published
checksum before executing it; do not replace it with an unpinned registry
command. See [distribution status](distribution-status.md) for dated npm, Homebrew, crates.io, and MCP Registry evidence. Prefer the checksum-verified `v0.7.9` GitHub assets for an exact install.
Select the matching asset for ARM64 or a non-Linux runner.

## Vercel

```bash
# One-time or release-time: sync secrets to Vercel
phantom sync --platform vercel --project prj_xxxxx

# Or add to .phantom.toml:
# [[sync]]
# platform = "vercel"
# token_env = "VERCEL_TOKEN"
# project_id = "prj_xxxxx"
```

After configuring, `phantom sync` pushes vault secrets to Vercel environment variables. Your GitHub Actions workflow can then trigger a Vercel deploy using Vercel's standard GitHub integration or CLI.

### Observe the hosted deployment

The staged web application exposes two no-store, provider-free operational
routes:

- `GET /api/v1/health` returns coarse route/runtime liveness. It returns `200`
  even when deployment identity is unavailable so a monitor can distinguish an
  executing route from dependency or configuration readiness.
- `GET /api/v1/ready` returns `200` only when complete Vercel deployment identity,
  core auth configuration, and all applicable local configuration checks pass.
  Commissioned billing additionally requires structurally valid Stripe
  configuration; the personal-vault and team gates add no provider check.
  Otherwise it returns `503`.

Readiness is deliberately `configuration_only`. It does not call Supabase,
Stripe, Vercel, or a customer workflow, and therefore never establishes
provider or customer acceptance. Public responses expose only status, service,
and release version. Source revision, deployment ID/environment, validation
reasons, service commissioning state, credentials, and environment-variable
values remain outside the anonymous response contract.

Enable access to Vercel's
[system environment variables](https://vercel.com/docs/environment-variables/system-environment-variables)
in project settings so `VERCEL_GIT_COMMIT_SHA`, `VERCEL_DEPLOYMENT_ID`, and `VERCEL_ENV`
exist. This is external deployment configuration; source cannot enable or prove
it. Core configuration also requires the three Supabase variables in
`apps/web/.env.local.example`: both `NEXT_PUBLIC_*` variables must be valid at
build time and remain byte-for-byte consistent and valid at runtime; a
non-secret SHA-256 fingerprint binds the two phases. `SUPABASE_SERVICE_ROLE_KEY`
is validated only at runtime. Runtime injection cannot repair a browser bundle
built without or for a different public configuration. Exact `true` feature gates add only
their documented local requirements. A successful source build does not prove
runtime variables exist in the deployed environment.

After an authorized deployment, record both coarse endpoint responses and
collect the deployment identifier and source SHA from authenticated Vercel
deployment metadata. Then verify provider and
authenticated user flows separately. Do not promote a `200` readiness response
into a provider-activation or customer-acceptance claim.

## Railway

```bash
# Sync secrets to Railway
phantom sync --platform railway --project your-project-id
```

Railway is the other supported sync platform. Store the Railway token in the environment where you run `phantom sync`; Phantom reads the platform token at sync time and does not store it in `.phantom.toml`.

## EAS Build (Expo)

EAS does not support arbitrary local proxy injection during hosted builds. Sync or enter secrets into EAS using Expo's own secret-management flow, then keep `phantom check` in CI to prevent raw `.env` secrets from being committed.

## Docker

A Phantom-protected `.env` contains persistent `phm_` mappings, not usable
provider credentials. BuildKit secret mounts pass the selected file's bytes
through unchanged: mounting that `.env` does not resolve its placeholders.
Wrapping `docker build` in `phantom exec` does not make this a supported
credential-delivery path. Exec configures its direct child; it does not
configure the Docker daemon or forward session environment variables into
build steps. Its authenticated proxy binds loopback in the namespace where
Phantom runs, not the isolated build container's loopback.

For a build that genuinely requires a credential, use the build platform's
separately approved secret provisioning and
[BuildKit secret mounts](https://docs.docker.com/build/building/secrets/). Do not
export or reveal Phantom vault values to assemble a build input, bake secrets
into image layers, or copy vault/unlock material into an agent image. A
BuildKit mount is not itself Phantom's value-blind proxy boundary.

For an unattended worker using Phantom's supported routes:

- Install a pinned, verified native release for the worker's platform before
  starting the workload; see the installation guidance above.
- Have the operator provision and unlock the worker's vault through an
  approved setup outside agent authority. As noted in [GitHub Actions](#github-actions),
  direct headless Cloud pull has no supported non-interactive login flow;
  [`phantom login`](../crates/phantom-cli/src/commands/login.rs) requires
  attached stdin, stdout, and stderr terminals before accessing credentials
  or the network.
- Launch the worker with `phantom exec -- <worker command>` where the child
  can reach Phantom's loopback proxy. A separate pod or container with a
  different network namespace does not share that loopback. Do not expose the proxy on a public interface
  or enable host networking as a shortcut.
- Confirm the client honors the injected route URL and preserves its path.
  Placeholder presence alone is not proof of usable credentials; consult
  [CLI coverage](exec.md) and [the agent walkthrough](agents.md).
- Use [the value-free preflight](agent-preflight-contract.md) without
  `--vault` for project readiness. It does not prove vault unlock or provider
  acceptance. MCP effects are disabled by default. Follow the existing
  [MCP approval contract](../AGENTS.md#selected-mcp-tools): leave effects
  disabled unless the approval command and approval storage are outside
  the requesting agent's authority. Operator enablement does not remove
  the per-call confirmation and one-use approval-token requirements.

These are integration requirements, not a Kubernetes deployment manifest or
proof of container isolation. Keep resource, process-lifecycle, and network
policy decisions in the worker's deployment layer; Phantom is not a process
or network sandbox.

## General Pattern

For CI/CD today:

1. Protect local secrets with `phantom init`.
2. Sync deploy-time secrets to a supported platform with `phantom sync --platform vercel` or `phantom sync --platform railway`.
3. Run CI checks such as `phantom check`.
4. Let the deployment platform inject secrets into builds and runtime.

Do not use undocumented CI token environment variables for Phantom Cloud pulls. Direct cloud pull in CI will be documented here once the CLI supports it.
