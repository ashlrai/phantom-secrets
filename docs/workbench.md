# Phantom workbench

Phantom brings coding agents, projects, tools and review into one engineering workbench. Use **Work with me** to steer a conversation, or **Work for me** to define an outcome for an enrolled fleet. Both workspaces retain the same account and authority boundaries.

The workbench uses `phm` and the package `@ashlr/phantom`. Phantom Secrets uses the separate `phantom` executable. Secrets protects supported credential paths; installing it does not install or activate the workbench.

## Start with a useful task

1. Follow [Install and open Phantom](workbench-setup.md).
2. Select **Work with me**, create a chat and choose a scratch project or public repository.
3. Inspect **Resources**. Use an account already signed in through its provider CLI, or a configured tool-capable local model. Automatic selects an eligible resource; Advanced lets you select an account and model.
4. Give the agent a concrete task with observable acceptance criteria. Ask it to inspect existing patterns before changing code.
5. Review the diff, reported tools and context, and verification results. A successful agent message alone does not prove a delivered change.

Selecting a folder creates a project context. It does not enroll that repository for unattended work. Creating a chat, saving an outcome or changing workspaces does not start the resident fleet.

## Know where to look

| Surface | Use it for |
| --- | --- |
| Chat | Interactive work, tool/context reports, reasoning and source review |
| Fleet | Enrolled work, outcomes, tasks, proposals and recorded merge evidence |
| Resources | Account readiness, usage freshness, reserves and capacity |
| Needs you | Decisions, permissions and blocked work requiring an operator |
| Changes | Inspect the current diff before accepting a result |
| Growth and Lessons | Inspect retained learning and improvement evidence |

Use Command-K to find actions and Command-J to open Needs you. Connected MCP servers and CLIs retain their own permissions; listing a tool does not establish authentication or permission to use it.

## Choose an execution model

Interactive chat may use subscription-backed CLI accounts, configured API engines or local models. These resources have different quotas, costs and capabilities. A saved profile is configuration, not a qualified connection. Unknown usage is not zero usage.

An autonomous fleet additionally requires enrolled repositories, eligible resources and a valid standing grant. Follow [Fleet and autonomy](workbench-autonomy.md). The [agent quickstart](workbench-agents.md) gives coding agents a discovery-first setup contract.

## Documentation evidence

These public guides describe the 3.29.15 source snapshot reviewed on October 13, 2026. The site's release record identifies publication separately. They cannot report a particular user's installed version, account state or service readiness.

[Upstream quickstart](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/QUICKSTART.md) and [workbench guide](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/VERSE.md) provide deeper details. Use the installed CLI's help for the exact command surface.
