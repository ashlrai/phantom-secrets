import {
  PUBLIC_RELEASE_TAG,
  PUBLIC_RELEASE_VERSION,
  PUBLIC_RELEASE_URL,
} from "@/lib/public-release";
import { QUESTIONS } from "./FAQ";

const SITE_URL = "https://phm.dev/secrets";
const DESCRIPTION = "Open-source, local-first credential boundary for AI coding agents. Managed dotenv values move to a local vault, and supported exact HTTP routes receive route-owned authentication.";

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
      text: `Install the pinned public release from ${PUBLIC_RELEASE_URL} and verify its published SHA-256 receipt. On macOS, review and explicitly trust the project formula before installing it; Homebrew publication evidence is separate from the GitHub release receipt. On Linux or Windows, checksum-verify the exact ${PUBLIC_RELEASE_TAG} GitHub asset. Current ${PUBLIC_RELEASE_TAG} Linux users begin with the non-reboot-persistent keyutils backend, or configure the encrypted-file backend before initialization when persistence is required. Then run phantom init in the project root.`,
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
        {/* JSON-LD: SoftwareApplication */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: serializeStructuredData({
              "@context": "https://schema.org",
              "@type": "SoftwareApplication",
              name: "Phantom Secrets",
              alternateName: "Phantom Secrets",
              applicationCategory: "DeveloperApplication",
              applicationSubCategory: "SecretsManagement",
              operatingSystem: "macOS, Linux, Windows",
              url: SITE_URL,
              sameAs: [
                "https://github.com/ashlrai/phantom-secrets",
              ],
              codeRepository: "https://github.com/ashlrai/phantom-secrets",
              programmingLanguage: "Rust",
              isAccessibleForFree: true,
              featureList: [
                "Local-first vault using OS credential stores or a ChaCha20-Poly1305 encrypted-file backend",
                "Authenticated exact-route HTTP credential injection",
                "Value-blind MCP tools for coding agents",
                "Claude Code, Cursor, Windsurf, and Codex setup",
                "macOS, Linux, and Windows release artifacts",
              ],
              license: "https://opensource.org/licenses/MIT",
              softwareVersion: PUBLIC_RELEASE_VERSION,
              downloadUrl: PUBLIC_RELEASE_URL,
              description: DESCRIPTION,
              offers: {
                "@type": "Offer",
                price: "0",
                priceCurrency: "USD",
                availability: "https://schema.org/InStock",
              },
              author: {
                "@type": "Organization",
                name: "AshlrAI, Inc.",
                url: "https://ashlr.ai",
              },
            }),
          }}
        />
        {/* JSON-LD: SoftwareSourceCode */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: serializeStructuredData({
              "@context": "https://schema.org",
              "@type": "SoftwareSourceCode",
              name: "Phantom Secrets",
              codeRepository: "https://github.com/ashlrai/phantom-secrets",
              runtimePlatform: "macOS, Linux, Windows",
              programmingLanguage: "Rust",
              license: "https://opensource.org/licenses/MIT",
              description: DESCRIPTION,
              targetProduct: {
                "@type": "SoftwareApplication",
                name: "Phantom Secrets",
                applicationCategory: "DeveloperApplication",
              },
            }),
          }}
        />
        {/* JSON-LD: HowTo */}
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
