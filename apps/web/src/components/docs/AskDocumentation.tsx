"use client";

import { useState } from "react";
import { DOCUMENTATION_ASSISTANTS, documentationAssistantLink } from "@/lib/documentation-assistant.mjs";

export function AskDocumentation({ path }: { path: string }) {
  const [provider, setProvider] = useState("chatgpt");
  const [copyState, setCopyState] = useState("");
  const link = documentationAssistantLink(provider, path);

  async function copyPrompt() {
    try {
      await navigator.clipboard.writeText(link.prompt);
      setCopyState("Prompt copied. Paste it into your assistant if needed.");
    } catch {
      setCopyState("Copy unavailable. Select the prompt below and copy it manually.");
    }
  }

  return (
    <details className="docs-assistant">
      <summary>Explain this guide with AI</summary>
      <div className="docs-assistant__body">
        <p>Choose your assistant. Only this public guide link and the prompt below are shared when you open it.</p>
        <label>
          <span>AI assistant</span>
          <select value={provider} onChange={(event) => { setProvider(event.target.value); setCopyState(""); }}>
            {DOCUMENTATION_ASSISTANTS.map(({ id, name }) => <option key={id} value={id}>{name}</option>)}
          </select>
        </label>
        <div className="docs-assistant__actions">
          <a href={link.href} target="_blank" rel="noopener noreferrer">Open {DOCUMENTATION_ASSISTANTS.find(({ id }) => id === provider)?.name}<span className="sr-only"> in a new tab</span></a>
          <button type="button" onClick={() => { void copyPrompt(); }}>Copy prompt</button>
        </div>
        <p>{link.attemptsPrefill ? "The link tries to fill the prompt. Sign-in or provider changes may require you to paste it yourself." : "Copy the prompt, open your assistant, then paste it into a new conversation."}</p>
        <textarea aria-label="Public documentation prompt" readOnly rows={5} value={link.prompt} />
        <p role="status" aria-live="polite">{copyState}</p>
      </div>
    </details>
  );
}
