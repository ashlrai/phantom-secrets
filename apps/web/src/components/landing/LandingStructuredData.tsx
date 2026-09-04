import {
  PUBLIC_RELEASE_TAG,
  PUBLIC_RELEASE_URL,
} from "@/lib/public-release";
import { QUESTIONS } from "./FAQ";

const howTo = {
  "@context": "https://schema.org",
  "@type": "HowTo",
  name: "Install Phantom Secrets",
  description:
    "Set up Phantom so supported AI-agent workflows receive placeholders instead of real API keys.",
  tool: [
    {
      "@type": "HowToTool",
      name: `Homebrew on macOS, or an exact ${PUBLIC_RELEASE_TAG} GitHub release asset`,
    },
    {
      "@type": "HowToTool",
      name: "Claude Code, Cursor, Windsurf, or Codex",
    },
  ],
  step: [
    {
      "@type": "HowToStep",
      name: "Install Phantom and protect your .env",
      text: `Install the reviewed release from ${PUBLIC_RELEASE_URL}. On macOS use the trusted Homebrew formula; on Linux or Windows, checksum-verify the exact ${PUBLIC_RELEASE_TAG} GitHub asset. Then run phantom init in the project root.`,
    },
    {
      "@type": "HowToStep",
      name: "Register the MCP server with your editor",
      text: `Install both ${PUBLIC_RELEASE_TAG} binaries, run phantom setup for Claude Code, Cursor, Windsurf, or Codex, and review the generated local MCP entry. The released setup path has no network package-runner fallback.`,
    },
    {
      "@type": "HowToStep",
      name: "Launch a bounded proxy session",
      text: "Use phantom exec to launch a child process with authenticated base-URL overrides for supported HTTP SDK routes. Exact matched routes receive only their route-owned authentication; client placeholders stay inert and unsupported database connection strings fail closed.",
    },
  ],
};

const faqPage = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  mainEntity: QUESTIONS.map(({ q, schemaAnswer }) => ({
    "@type": "Question",
    name: q,
    acceptedAnswer: {
      "@type": "Answer",
      text: schemaAnswer,
    },
  })),
};

function serializeStructuredData(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

export function LandingStructuredData() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: serializeStructuredData(howTo) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: serializeStructuredData(faqPage) }}
      />
    </>
  );
}
