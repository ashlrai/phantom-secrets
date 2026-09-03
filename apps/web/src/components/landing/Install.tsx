"use client";

import { useState } from "react";
import { CopyButton } from "./CopyButton";

const CLIENTS = [
  {
    id: "claude",
    label: "Claude Code",
    command: "phantom setup --client claude",
    config: ".claude/settings.local.json",
    scope: "project",
  },
  {
    id: "cursor",
    label: "Cursor",
    command: "phantom setup --client cursor",
    config: "~/.cursor/mcp.json",
    scope: "user",
  },
  {
    id: "windsurf",
    label: "Windsurf",
    command: "phantom setup --client windsurf",
    config: "~/.codeium/windsurf/mcp_config.json",
    scope: "user",
  },
  {
    id: "codex",
    label: "Codex",
    command: "phantom setup --client codex",
    config: "~/.codex/config.toml",
    scope: "user",
  },
] as const;

type ClientId = (typeof CLIENTS)[number]["id"];

export function Install() {
  const [active, setActive] = useState<ClientId>("claude");
  const client = CLIENTS.find((item) => item.id === active) ?? CLIENTS[0];

  return (
    <section id="install" className="connection-section">
      <div className="landing-frame connection-section__layout">
        <div className="landing-section-heading connection-section__heading">
          <p className="landing-kicker">Client connection</p>
          <h2>Put the value-blind tools where agents work.</h2>
          <p>
            After installing both reviewed v0.7.4 binaries, write the supported
            client&apos;s local MCP entry and inspect the generated file. Setup uses
            a local Phantom runtime and has no network package-runner fallback.
          </p>
          <a
            href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md"
            className="landing-text-link"
          >
            Read the complete installation and verification guide
          </a>
        </div>

        <div className="connection-console">
          <div className="connection-console__tabs" role="group" aria-label="Choose an AI client">
            {CLIENTS.map((item) => (
              <button
                key={item.id}
                type="button"
                aria-pressed={active === item.id}
                onClick={() => setActive(item.id)}
              >
                {item.label}
              </button>
            ))}
          </div>

          <div
            className="connection-console__panel"
            aria-live="polite"
          >
            <dl>
              <div>
                <dt>Writes</dt>
                <dd><code>{client.config}</code></dd>
              </div>
              <div>
                <dt>Scope</dt>
                <dd>{client.scope}</dd>
              </div>
              <div>
                <dt>Runtime</dt>
                <dd>installed local binary</dd>
              </div>
            </dl>
            <CopyButton text={client.command} />
            <p>
              Review the diff before restarting {client.label}. Registration
              does not activate cloud service or production execution authority.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
