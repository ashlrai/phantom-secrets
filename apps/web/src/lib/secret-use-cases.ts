export interface ClaimSource {
  label: string;
  href: string;
}

export interface UseCaseClaim {
  id: string;
  title: string;
  paragraphs: readonly string[];
  command?: string;
  sources: readonly [ClaimSource, ...ClaimSource[]];
}

export interface SecretUseCase {
  slug: string;
  title: string;
  description: string;
  introduction: UseCaseClaim;
  steps: readonly UseCaseClaim[];
  limits: UseCaseClaim;
}

const gettingStarted = { label: "Getting started", href: "/docs/getting-started" };
const delegation = { label: "Safe delegation guide", href: "/docs/delegation-quickstart" };
const protection = { label: "API key protection guide", href: "/docs/protect-api-keys-from-ai-coding-agents" };
const troubleshooting = { label: "Troubleshooting guide", href: "/docs/troubleshooting" };

export const SECRET_USE_CASES: readonly SecretUseCase[] = [
  {
    slug: "ai-api-development",
    title: "Develop an API integration with an AI coding agent",
    description: "Plan a bounded API integration task, protect managed dotenv credentials, and verify Phantom's supported local proxy workflow before delegating.",
    introduction: {
      id: "fit", title: "Start with a bounded development task",
      paragraphs: ["An API integration often needs both code changes and a credentialed request. Phantom separates those concerns: managed dotenv values move into a local vault, while supported HTTP requests use an authenticated local proxy. Begin with a non-production integration and a task you can verify locally."],
      sources: [protection, delegation],
    },
    steps: [
      {
        id: "prepare", title: "1. Protect the project before opening the agent",
        paragraphs: ["Install a reviewed release using the installation guide. Keep an independent recovery copy of each credential in the provider console or an approved password manager. From a terminal you control, initialize the intended project, then inspect names and protection state. Initialization changes the managed dotenv file and does not leave a plaintext project backup."],
        command: "phantom init\nphantom list\nphantom check",
        sources: [gettingStarted, delegation],
      },
      {
        id: "scope", title: "2. Give the agent a narrow task contract",
        paragraphs: ["Name the repository, objective, permitted files, secret names and required tests. A useful first task is adding a provider client behind an existing interface and testing it against a local stub. State separately whether any live request is allowed. Local readiness does not authorize deployment, provider changes or billing actions.", "For missing credentials, ask the operator to use phantom add NAME in a trusted terminal. Never put the value in chat or tool arguments. The MCP interactive-add tool returns this command; it does not receive or store the value."],
        sources: [delegation, { label: "Value-blind MCP guide", href: "/docs/mcp-secrets-manager" }],
      },
      {
        id: "run", title: "3. Launch the supported client through the proxy",
        paragraphs: ["Inspect local readiness before launching your client. The example below uses Codex; the client guides also describe Claude Code, Cursor and Windsurf. Phantom configures implemented SDK base-URL overrides for the child. Exact matched routes inject their own credential into a fixed authentication header; client headers and bodies do not select vault values."],
        command: "phantom agent doctor\nphantom exec -- codex",
        sources: [delegation, { label: "Codex setup", href: "/docs/codex" }, protection],
      },
      {
        id: "verify", title: "4. Close the task with evidence",
        paragraphs: ["Review the diff and run the repository's focused tests. Check agent output, patches and logs for credential disclosure without copying protected mappings into a report. Record local tests separately from any authorized provider request. After the proxy stops, its old session authorization is invalid."],
        command: "phantom check\ngit diff --check\ngit status --short",
        sources: [delegation, protection],
      },
    ],
    limits: {
      id: "limits", title: "Decide whether this boundary fits",
      paragraphs: ["Phantom is not a process sandbox and does not make an untrusted same-user process safe. Unsupported protocols are not silently protected: database drivers do not use the HTTP proxy, and protected database URLs are not restored into the child environment. Existing disclosures in history or unrelated files still need separate remediation."],
      sources: [protection, { label: "Threat model", href: "https://github.com/ashlrai/phantom-secrets/blob/main/THREAT_MODEL.md" }],
    },
  },
  {
    slug: "multi-project-setup",
    title: "Protect API keys across several local repositories",
    description: "Preview Phantom's bounded repository scan, review nested-project exclusions, and verify each local project before using an AI coding agent.",
    introduction: {
      id: "fit", title: "Make the repository list explicit",
      paragraphs: ["When several local repositories contain dotenv credentials, Phantom can preview and initialize eligible projects in a workspace. Treat the preview as the starting inventory. The scanner has deliberate depth and nesting limits, so one workspace command does not prove that every project or secret has been covered."],
      sources: [gettingStarted],
    },
    steps: [
      {
        id: "preview", title: "1. Preview the exact workspace",
        paragraphs: ["Install the reviewed CLI and keep independent recoverable copies of credentials before initialization. Run a dry run against the directory you intend to protect, then review the listed repositories before applying changes."],
        command: "phantom init --all ~/code --dry-run",
        sources: [gettingStarted, delegation],
      },
      {
        id: "coverage", title: "2. Account for nested and excluded projects",
        paragraphs: ["The scan searches at most five directory levels for repositories containing a supported dotenv filename. It stops descending below the first matching repository and skips already-protected repositories, dot-directories and known dependency or build directories.", "Deeper or nested repositories may need their own invocation. In a monorepo, inspect the intended dotenv path instead of assuming the workspace scan initializes every application directory. For a selected project, the documented explicit-file form is phantom init --from .env.local."],
        sources: [gettingStarted, { label: "Repository scanner implementation", href: "https://github.com/ashlrai/phantom-secrets/blob/main/crates/phantom-cli/src/commands/init/multi.rs" }],
      },
      {
        id: "apply", title: "3. Apply the reviewed selection",
        paragraphs: ["Run the workspace command from a trusted terminal only after reviewing the preview. Initialization stores detected values and rewrites managed dotenv entries with persistent mappings. Those mappings are sensitive metadata; do not paste them into issues or agent chat."],
        command: "phantom init --all ~/code",
        sources: [gettingStarted, { label: "MCP metadata boundary", href: "/docs/mcp-secrets-manager" }],
      },
      {
        id: "verify", title: "4. Verify each project in its own directory",
        paragraphs: ["Check each intended repository's secret names, dotenv scan and local readiness before delegating work there. A successful command in one repository is evidence for that checkout, not for a neighboring project. Connect the selected coding client and use phantom exec for its supported credentialed work."],
        command: "phantom list\nphantom check\nphantom agent doctor",
        sources: [delegation, protection],
      },
    ],
    limits: {
      id: "limits", title: "Stop on an uncertain write",
      paragraphs: ["Do not blindly rerun after a CommittedButUncertain, durability or Partial warning. A write may already have committed. Use phantom doctor and inspect the intended project from a trusted terminal before retrying. Workspace initialization is local protection; it does not establish hosted sync, team entitlement or organizational acceptance."],
      sources: [gettingStarted, delegation],
    },
  },
  {
    slug: "debug-api-authentication",
    title: "Diagnose API authentication without exposing the key",
    description: "Use secret names and Phantom delivery diagnostics to distinguish missing project state, unsupported routes and locked vaults before retrying an API request.",
    introduction: {
      id: "fit", title: "Inspect the delivery path before the value",
      paragraphs: ["A 401 response after launching an agent does not by itself identify the problem. Check the project, the protected name and the route first. Phantom's why command explains whether a key is protected and how phantom exec delivers it without displaying the credential value."],
      sources: [troubleshooting, { label: "Secret explainer implementation", href: "https://github.com/ashlrai/phantom-secrets/blob/main/crates/phantom-cli/src/commands/why.rs" }],
    },
    steps: [
      {
        id: "project", title: "1. Confirm the project and exact name",
        paragraphs: ["Run these checks in the repository you initialized. Secret names are case-sensitive. A missing entry can mean you are in another project, used a different name or initialized the vault on another machine. Use the JSON why report for value-free delivery diagnostics, and report only names and metadata; persistent mappings are not public identifiers."],
        command: "phantom status\nphantom list\nphantom why OPENAI_API_KEY --json",
        sources: [troubleshooting, { label: "MCP inspection guide", href: "/docs/mcp-secrets-manager" }, { label: "Value-free why report", href: "https://github.com/ashlrai/phantom-secrets/blob/main/crates/phantom-core/src/why.rs" }],
      },
      {
        id: "route", title: "2. Distinguish a missing route from a rejected credential",
        paragraphs: ["If delivery reports no_route, no built-in proxy route injects that protected key. The child receives a session placeholder that the provider will not accept. Replacing it with the real key in an agent-visible file defeats the intended workflow; stop and evaluate a supported path instead.", "phantom exec refuses custom routes from repository configuration. A person can review custom routes for foreground phantom start, but that is a separate operator workflow, not an automatic fix for agent execution."],
        sources: [troubleshooting, protection],
      },
      {
        id: "vault", title: "3. Treat a locked vault as unavailable, not empty",
        paragraphs: ["A locked encrypted-file vault causes inventory tools to refuse an answer rather than report an empty alternate backend. The MCP error is -32600. Have the operator follow the vault-specific unlock guidance outside agent context and retry or restart the MCP server. Do not delete the vault or recreate its entries based on an unavailable inventory."],
        sources: [troubleshooting],
      },
      {
        id: "retry", title: "4. Retry only the intended supported request",
        paragraphs: ["For supported clients, phantom exec sets implemented SDK base-URL overrides and starts an authenticated loopback proxy. Do not hardcode a proxy port; the operating system selects a free port for each launch. Run a bounded, authorized non-production request and record its result separately from local configuration checks."],
        command: "phantom agent doctor\nphantom exec -- codex",
        sources: [troubleshooting, delegation, { label: "Codex proxy workflow", href: "/docs/codex" }],
      },
    ],
    limits: {
      id: "limits", title: "Know what the diagnosis does not prove",
      paragraphs: ["Local readiness and metadata do not establish provider permission, hosted-service availability or deployment acceptance. Phantom does not erase credentials previously exposed in logs or history. If disclosure occurred, use the provider's revocation or rotation process and update the vault from a trusted terminal."],
      sources: [delegation, protection],
    },
  },
];

export function getSecretUseCase(slug: string): SecretUseCase | undefined {
  return SECRET_USE_CASES.find((entry) => entry.slug === slug);
}

export function secretUseCasePath(slug: string): string {
  return `/secrets/use-cases/${slug}`;
}
