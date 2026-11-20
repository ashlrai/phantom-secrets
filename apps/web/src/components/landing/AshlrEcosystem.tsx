// Mirrors the README's "Part of the Ashlr ecosystem" section. Keep names,
// commands, and links in sync with it; tests/ashlr-ecosystem.test.cjs checks
// that every link here also appears in the README.
const TOOLS = [
  {
    name: "Phantom",
    command: "phm",
    body: "The agent workbench for chats, projects, traces, and review.",
    href: "https://github.com/ashlrai/phantom",
  },
  {
    name: "Phantom Secrets",
    command: "phantom",
    body: "This product. Keeps real API keys out of supported agent paths with a local vault and exact-route injection.",
    href: "https://github.com/ashlrai/phantom-secrets",
  },
  {
    name: "Locus",
    command: "locus",
    body: "Pins each agent session to one account. Phantom Secrets ships only an inactive compatibility contract for it today.",
    href: "https://github.com/ashlrai/locus",
  },
  {
    name: "Lexicon",
    command: "lexicon",
    body: "Fixes the words dictation gets wrong.",
    href: "https://lexicon.ashlr.ai",
  },
  {
    name: "Ashlr MD",
    command: null,
    body: "A Markdown app with an MCP server.",
    href: "https://md.ashlr.ai",
  },
  {
    name: "Ashlr Stack",
    command: "stack",
    body: "Provisions services and stores their keys in Phantom Secrets.",
    href: "https://stack.ashlr.ai",
  },
  {
    name: "ashlr-plugin",
    command: "ashlr-plugin",
    body: "Token-efficiency tools for Claude Code and Codex.",
    href: "https://plugin.ashlr.ai/",
  },
] as const;

export function AshlrEcosystem() {
  return (
    <section id="ashlr-ecosystem" className="ashlr-ecosystem" aria-labelledby="ashlr-ecosystem-title">
      <div className="landing-frame">
        <div className="landing-section-heading">
          <p className="landing-kicker">Part of the Ashlr ecosystem</p>
          <h2 id="ashlr-ecosystem-title">One open-source tool in an agent-run software factory.</h2>
        </div>
        <p className="ashlr-ecosystem__mission">
          Phantom Secrets is one of the open-source tools from <a href="https://ashlr.ai">Ashlr</a>.
          Together they aim to be an autonomous, code-first, agent-native software
          factory: agents write, test, review, and ship the code, and the human acts
          as a passive board member. The long-term goal is open-source recursive
          self-improvement (RSI), where agents improve the tools they build with.
          Each tool installs and runs on its own.
        </p>

        <ul className="ashlr-ecosystem__list">
          {TOOLS.map((tool) => (
            <li key={tool.name}>
              <a href={tool.href}><strong>{tool.name}</strong></a>
              {tool.command && <code>{tool.command}</code>}
              <p>{tool.body}</p>
            </li>
          ))}
        </ul>

        <p className="ashlr-ecosystem__agents">
          Coding agents make most changes to Phantom Secrets through the same pull
          requests and CI as any contributor. They follow{" "}
          <a href="https://github.com/ashlrai/phantom-secrets/blob/main/AGENTS.md">AGENTS.md</a>,
          run the checks in{" "}
          <a href="https://github.com/ashlrai/phantom-secrets/blob/main/CLAUDE.md">CLAUDE.md</a>,
          and use only value-free commands such as <code>phantom status --json</code>.
          A person or agent can follow{" "}
          <a href="https://github.com/ashlrai/phantom-secrets/blob/main/CONTRIBUTING.md#contribute-with-an-agent">
            Contribute with an agent
          </a>{" "}
          from a fork to a merged pull request: <code>CI Gate</code> is the only
          required check, and fork contributors need no write access or repository
          secrets.
        </p>
      </div>
    </section>
  );
}
