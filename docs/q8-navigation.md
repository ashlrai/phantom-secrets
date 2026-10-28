# Find your way through Phantom

Choose the task you want to do. Each route starts with a practical guide and
points to the next reference when you need more detail. The [documentation
index](README.md) is the broader catalog.

| Your task | Start here | Then, if needed |
| --- | --- | --- |
| Install Phantom and protect a project | [Getting started](getting-started.md) | Check [platform support](platform-support.md) and dated [distribution status](distribution-status.md). |
| Give an AI coding agent a bounded task | [Safe delegation quickstart](delegation-quickstart.md) | Review [agent integration](agents.md), [exec and proxy behavior](exec.md), and the [threat model](../THREAT_MODEL.md). |
| Set up your coding client | [Claude Code](claude-code.md), [Codex](codex.md), [Cursor](cursor.md), or [Windsurf](windsurf.md) | Use the [MCP secrets manager guide](mcp-secrets-manager.md) for the tool model. |
| Check or troubleshoot a setup | [Troubleshooting](troubleshooting.md) | Review [exec](exec.md) for proxy delivery and [platform support](platform-support.md) for platform limitations. |
| Separate keys between projects | [Multi-project key separation](multi-project-keys.md) | See [getting started](getting-started.md) for initial protection. |
| Create a local generated secret | [Generated secrets](generated-secrets.md) | See the [MCP guide](mcp-secrets-manager.md) for agent workflows. |
| Deploy or use CI | [Vercel and Railway sync](sync.md) or [CI/CD integration](ci-cd.md) | Review the [security evaluation](security-evaluation.md) before extending access. |
| Evaluate security or plan a pilot | [Security evaluation](security-evaluation.md) | Use the [audit index](audit-index.md), [architecture](architecture.md), and [enterprise adoption guide](enterprise-adoption.md). |
| Contribute or report a problem | [Contributing](../CONTRIBUTING.md) | Use [support](../SUPPORT.md) or the private reporting route in the [security policy](../SECURITY.md). |

For a first agent workflow, protect the project first, configure the client,
then follow the delegation guide. Keep real secret values out of chat and
source files; managed mappings are sensitive metadata too. The proxy only
injects credentials for supported matched routes, so consult [exec](exec.md)
and the [threat model](../THREAT_MODEL.md) for the boundary.

Cloud and team workflows require a separately commissioned service and account
entitlement. See [cloud login](login.md) and [distribution status](distribution-status.md)
for current evidence and limits.
