"use client";

import { useState } from "react";

const INSTALL = "brew tap ashlrai/phantom && brew trust --formula ashlrai/phantom/phantom && brew install ashlrai/phantom/phantom";

const COMMANDS = `phantom init
phantom status --json
phantom list --json
phantom agent doctor --json
phantom setup --client claude
phantom setup --client cursor
phantom setup --client codex
phantom check
phantom why OPENAI_API_KEY --json`;

const MCP_JSON = `{
  "mcpServers": {
    "phantom": {
      "command": "phantom",
      "args": ["mcp", "serve"]
    }
  }
}`;

const CODEX_TOML = `[mcp_servers.phantom]
command = "phantom"
args = ["mcp", "serve"]`;

type PanelId = "install" | "commands" | "claude" | "cursor" | "codex";

const PANELS: { id: PanelId; label: string }[] = [
  { id: "install", label: "Install" },
  { id: "commands", label: "JSON commands" },
  { id: "claude", label: "Claude" },
  { id: "cursor", label: "Cursor" },
  { id: "codex", label: "Codex" },
];

function panelCopy(id: PanelId): { file: string; body: string; note: string } {
  switch (id) {
    case "install":
      return {
        file: "macOS",
        body: INSTALL,
        note: "Linux and Windows use the checksum-checked archive in the install guide. This line is the macOS paste.",
      };
    case "commands":
      return {
        file: "project directory",
        body: COMMANDS,
        note: "status, list, and why print names and state. They do not print secret values.",
      };
    case "claude":
      return {
        file: ".mcp.json",
        body: MCP_JSON,
        note: "phantom setup --client claude writes this file and fills command with the binary path it found.",
      };
    case "cursor":
      return {
        file: "~/.cursor/mcp.json",
        body: MCP_JSON,
        note: "phantom setup --client cursor writes this file. Restart Cursor after it lands.",
      };
    case "codex":
      return {
        file: "~/.codex/config.toml",
        body: CODEX_TOML,
        note: "phantom setup --client codex writes this table. Restart Codex after it lands.",
      };
    default: {
      const never: never = id;
      return never;
    }
  }
}

export function AgentQuickstart() {
  const [panel, setPanel] = useState<PanelId>("commands");
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const current = panelCopy(panel);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(current.body);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
    window.setTimeout(() => setCopyState("idle"), 1800);
  };

  return (
    <section id="agent" className="agent-console" aria-labelledby="agent-console-title">
      <div className="landing-frame">
        <p className="landing-kicker">For agents</p>
        <h2 id="agent-console-title">Paste this. Then read JSON.</h2>
        <p>
          Phantom is a local vault and a loopback proxy. An agent installs it, asks for
          value-free JSON, and connects Claude, Cursor, or Codex with one setup command.
        </p>
        <div className="agent-console__tabs" role="tablist" aria-label="Agent quickstart">
          {PANELS.map((item) => (
            <button
              type="button"
              key={item.id}
              role="tab"
              id={`agent-tab-${item.id}`}
              aria-selected={panel === item.id}
              aria-controls="agent-panel"
              onClick={() => {
                setPanel(item.id);
                setCopyState("idle");
              }}
            >
              {item.label}
            </button>
          ))}
        </div>
        <div
          role="tabpanel"
          id="agent-panel"
          aria-labelledby={`agent-tab-${panel}`}
          className="agent-console__panel"
        >
          <div className="agent-console__bar">
            <span>{current.file}</span>
            <button type="button" onClick={() => void copy()}>
              {copyState === "copied" ? "Copied" : copyState === "failed" ? "Copy failed" : "Copy"}
            </button>
          </div>
          <pre><code>{current.body}</code></pre>
          <p>{current.note}</p>
        </div>
        <p className="agent-console__links">
          <a href="/llms.txt">llms.txt</a>
          <a href="/llms-full.txt">llms-full.txt</a>
              <a href="https://github.com/ashlrai/phantom-secrets">Open the repository</a>
        </p>
      </div>
    </section>
  );
}
