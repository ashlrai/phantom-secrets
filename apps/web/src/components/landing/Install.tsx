"use client";

import Link from "next/link";
import { useState } from "react";
import { PUBLIC_RELEASE_TAG } from "@/lib/public-release";
import {
  ClaudeClientLogo,
  CodexClientLogo,
  CursorClientLogo,
  WindsurfClientLogo,
} from "./ClientLogos";
import { CopyButton } from "./CopyButton";

const CLIENTS = [
  {
    id: "claude",
    label: "Claude Code",
    Logo: ClaudeClientLogo,
    preview: "phantom setup --client claude --print",
    command: "phantom setup --client claude",
    launch: "phantom exec -- claude",
    config: ".claude/settings.local.json",
    scope: "project",
  },
  {
    id: "cursor",
    label: "Cursor",
    Logo: CursorClientLogo,
    preview: "phantom setup --client cursor --print",
    command: "phantom setup --client cursor",
    launch: "phantom exec -- cursor .",
    config: "~/.cursor/mcp.json",
    scope: "user",
  },
  {
    id: "windsurf",
    label: "Windsurf",
    Logo: WindsurfClientLogo,
    preview: "phantom setup --client windsurf --print",
    command: "phantom setup --client windsurf",
    launch: "phantom exec -- windsurf .",
    config: "~/.codeium/windsurf/mcp_config.json",
    scope: "user",
  },
  {
    id: "codex",
    label: "Codex",
    Logo: CodexClientLogo,
    preview: "phantom setup --client codex --print",
    command: "phantom setup --client codex",
    launch: 'phantom exec -- codex "<your task>"',
    config: "~/.codex/config.toml",
    scope: "user",
  },
] as const;

type ClientId = (typeof CLIENTS)[number]["id"];

export function Install() {
  const [active, setActive] = useState<ClientId>("claude");
  const client = CLIENTS.find((item) => item.id === active) ?? CLIENTS[0];

  function selectAdjacentClient(currentId: ClientId, offset: number) {
    const currentIndex = CLIENTS.findIndex((item) => item.id === currentId);
    const nextIndex = (currentIndex + offset + CLIENTS.length) % CLIENTS.length;
    const next = CLIENTS[nextIndex];
    setActive(next.id);
    document.getElementById(`client-tab-${next.id}`)?.focus();
  }

  return (
    <section id="connect" className="connection-section">
      <div className="landing-frame connection-section__layout">
        <div className="landing-section-heading connection-section__heading">
          <p className="landing-kicker">Client connection</p>
          <h2>Put the value-blind tools where agents work.</h2>
          <p>
            After installing both pinned {PUBLIC_RELEASE_TAG} binaries, preview the supported
            client&apos;s local MCP entry before writing it. Setup uses
            a local Phantom runtime and has no network package-runner fallback.
          </p>
          <Link href="/docs/getting-started" className="landing-text-link">
            Read the complete installation and verification guide
          </Link>
        </div>

        <div className="connection-console">
          <div className="connection-console__tabs" role="tablist" aria-label="Choose an AI client">
            {CLIENTS.map((item) => (
              <button
                key={item.id}
                id={`client-tab-${item.id}`}
                type="button"
                role="tab"
                aria-selected={active === item.id}
                aria-controls="client-connection-panel"
                tabIndex={active === item.id ? 0 : -1}
                onClick={() => setActive(item.id)}
                onKeyDown={(event) => {
                  if (event.key === "ArrowRight") {
                    event.preventDefault();
                    selectAdjacentClient(item.id, 1);
                  } else if (event.key === "ArrowLeft") {
                    event.preventDefault();
                    selectAdjacentClient(item.id, -1);
                  } else if (event.key === "Home") {
                    event.preventDefault();
                    setActive(CLIENTS[0].id);
                    document.getElementById(`client-tab-${CLIENTS[0].id}`)?.focus();
                  } else if (event.key === "End") {
                    event.preventDefault();
                    const last = CLIENTS[CLIENTS.length - 1];
                    setActive(last.id);
                    document.getElementById(`client-tab-${last.id}`)?.focus();
                  }
                }}
              >
                <item.Logo className="connection-console__client-logo" aria-hidden="true" />
                {item.label}
              </button>
            ))}
          </div>

          <div
            id="client-connection-panel"
            className="connection-console__panel"
            role="tabpanel"
            aria-labelledby={`client-tab-${client.id}`}
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
            <p>
              Preview the exact MCP entry. This command does not write the client configuration.
            </p>
            <CopyButton text={client.preview} />
            <p>
              After review, apply the same client choice from a trusted terminal.
            </p>
            <CopyButton text={client.command} />
            <p>
              Inspect the written file before restarting {client.label}. Registration
              does not activate cloud service or production execution authority.
            </p>
            <p>
              Restart {client.label}, verify the local boundary, then launch that
              same client through the supervised proxy session.
            </p>
            <CopyButton text={`phantom agent doctor\n${client.launch}`} />
          </div>
        </div>
      </div>
    </section>
  );
}
