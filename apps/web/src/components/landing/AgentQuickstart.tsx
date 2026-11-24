"use client";

import { useState } from "react";

// The Homebrew formula still serves v0.7.9, which rejects `agent doctor --json`
// from COMMANDS below, so this panel installs the v0.8.7 release archive instead.
const INSTALL = `archive=phantom-aarch64-apple-darwin.tar.gz
base=https://github.com/ashlrai/phantom-secrets/releases/download/v0.8.11
curl -fsSL -o "$archive" "$base/$archive"
curl -fsSL -o "$archive.sha256" "$base/$archive.sha256"
shasum -a 256 -c "$archive.sha256"
tar -xzf "$archive"
mkdir -p "$HOME/.local/bin"
install -m 0755 phantom phantom-mcp "$HOME/.local/bin/"
export PATH="$HOME/.local/bin:$PATH"`;

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
        file: "macOS Apple Silicon (v0.8.7)",
        body: INSTALL,
        note: "Other platforms swap in their archive name from the install guide. Homebrew still serves v0.7.9, which lacks agent doctor --json.",
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
