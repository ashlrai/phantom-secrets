import type { Metadata, Viewport } from "next";
import { Inter_Tight, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { PostHogProvider } from "./providers";

const sans = Inter_Tight({
  subsets: ["latin"],
  variable: "--font-sans-stack",
  display: "swap",
  weight: ["400", "500", "600", "700", "800"],
});

const mono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono-stack",
  display: "swap",
  weight: ["400", "500", "600", "700"],
});

const SITE_URL = "https://phm.dev";
const TITLE = "Phantom — Delegate credentialed API work to AI";
const DESCRIPTION =
  "Phantom gives supported AI-agent workflows placeholders while an authenticated local proxy resolves fresh session tokens only for configured upstreams. Works with Claude Code, Cursor, Windsurf, and Codex.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: TITLE,
    template: "%s — Phantom",
  },
  description: DESCRIPTION,
  applicationName: "Phantom",
  authors: [{ name: "AshlrAI", url: "https://ashlr.ai" }],
  creator: "AshlrAI",
  publisher: "AshlrAI",
  generator: "Next.js",
  keywords: [
    "API keys",
    "secrets management",
    "Claude Code",
    "Cursor",
    "Windsurf",
    "MCP",
    "developer tools",
    "open source",
    "Rust CLI",
    "AI security",
    "phantom tokens",
    "vault",
  ],
  category: "developer tools",
  alternates: {
    canonical: "/",
  },
  openGraph: {
    type: "website",
    url: SITE_URL,
    siteName: "Phantom",
    title: TITLE,
    description: DESCRIPTION,
    locale: "en_US",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "Phantom — the blue ghost holds a provider key while handing an AI workflow a phm_a8f2c4d9 placeholder.",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    site: "@ashlrai",
    creator: "@ashlrai",
    title: TITLE,
    description:
      "Supported AI workflows get placeholders. An authenticated local proxy resolves session tokens for configured upstreams. Open-source CLI for Claude Code, Cursor, Windsurf, and Codex.",
    images: ["/og-image.png"],
  },
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml" },
    ],
    apple: "/favicon.svg",
  },
  manifest: "/manifest.webmanifest",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
};

export const viewport: Viewport = {
  themeColor: "#050508",
  colorScheme: "dark",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <head>
        {/* AI agents — point them at the canonical machine-readable docs */}
        <link rel="alternate" type="text/markdown" href="/llms.txt" title="Phantom — LLM context" />
        <link rel="alternate" type="text/markdown" href="/llms-full.txt" title="Phantom — full LLM reference" />
        {/* JSON-LD: SoftwareApplication */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "SoftwareApplication",
              name: "Phantom",
              alternateName: "Phantom Secrets",
              applicationCategory: "DeveloperApplication",
              applicationSubCategory: "SecretsManagement",
              operatingSystem: "macOS, Linux, Windows",
              url: SITE_URL,
              sameAs: [
                "https://github.com/ashlrai/phantom-secrets",
                "https://www.npmjs.com/package/phantom-secrets",
              ],
              license: "https://opensource.org/licenses/MIT",
              softwareVersion: "0.7.3",
              description: DESCRIPTION,
              offers: {
                "@type": "Offer",
                price: "0",
                priceCurrency: "USD",
                availability: "https://schema.org/InStock",
              },
              author: {
                "@type": "Organization",
                name: "AshlrAI",
                url: "https://ashlr.ai",
              },
            }),
          }}
        />
        {/* JSON-LD: Organization */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "Organization",
              name: "Phantom",
              url: SITE_URL,
              logo: `${SITE_URL}/favicon.svg`,
              sameAs: ["https://github.com/ashlrai/phantom-secrets"],
            }),
          }}
        />
        {/* JSON-LD: HowTo — install steps, surface for rich Google results
            and AI agent indexing */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "HowTo",
              name: "Install Phantom Secrets",
              description:
                "Set up Phantom so supported AI-agent workflows receive placeholders instead of real API keys.",
              totalTime: "PT1M",
              tool: [
                { "@type": "HowToTool", name: "Node.js (for npx)" },
                { "@type": "HowToTool", name: "Claude Code, Cursor, Windsurf, or Codex" },
              ],
              step: [
                {
                  "@type": "HowToStep",
                  name: "Install Phantom and protect your .env",
                  text: "Run `npx phantom-secrets init` in your project root. Phantom auto-detects API keys, stores them in an OS credential store when available or in its ChaCha20-Poly1305 encrypted-file fallback, and rewrites the .env with phm_ tokens.",
                },
                {
                  "@type": "HowToStep",
                  name: "Register the MCP server with your editor",
                  text: "Run `claude mcp add phantom-secrets-mcp -- npx -y phantom-secrets-mcp` for Claude Code, or paste the mcpServers JSON into Cursor / Windsurf MCP settings.",
                },
                {
                  "@type": "HowToStep",
                  name: "Run your code with the proxy injecting real keys",
                  text: "Use `phantom exec -- <command>` to launch a child process with authenticated base-URL overrides for Phantom's supported HTTP SDK routes. The local proxy resolves fresh session tokens only on configured upstream routes; unsupported connection strings fail closed.",
                },
              ],
            }),
          }}
        />
        {/* JSON-LD: FAQPage — common questions, surfaces in Google AI overviews */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "FAQPage",
              mainEntity: [
                {
                  "@type": "Question",
                  name: "Does Phantom slow down my AI requests?",
                  acceptedAnswer: {
                    "@type": "Answer",
                    text: "Phantom adds a local Rust HTTP proxy bound to 127.0.0.1. Request bodies are processed under byte and time limits; measure overhead in your own latency-critical workload.",
                  },
                },
                {
                  "@type": "Question",
                  name: "What does AI see when Phantom is installed?",
                  acceptedAnswer: {
                    "@type": "Answer",
                    text: "A managed .env file contains persistent phm_xxxxxxxx placeholders instead of provider credentials. phantom exec creates fresh child-session tokens, and the authenticated local proxy resolves them only for configured supported HTTP routes.",
                  },
                },
                {
                  "@type": "Question",
                  name: "What happens if a phm_ token leaks from AI logs?",
                  acceptedAnswer: {
                    "@type": "Answer",
                    text: "The managed .env phm_ placeholder persists until rotation and is not the provider credential. phantom exec separately creates fresh session phm_ values and a fresh PHANTOM_PROXY_TOKEN for the child; both stop working when that proxy session ends.",
                  },
                },
                {
                  "@type": "Question",
                  name: "How are real keys stored?",
                  acceptedAnswer: {
                    "@type": "Answer",
                    text: "OS keychain on macOS and Linux (Keychain / Secret Service). Encrypted file fallback for CI and Docker, using ChaCha20-Poly1305 with Argon2id key derivation.",
                  },
                },
                {
                  "@type": "Question",
                  name: "Which editors does Phantom work with?",
                  acceptedAnswer: {
                    "@type": "Answer",
                    text: "Phantom provides MCP setup for Claude Code, Cursor, Windsurf, and Codex. Other programs can run under phantom exec when their HTTP SDK accepts a supported base-URL override; protected database connection strings fail closed.",
                  },
                },
                {
                  "@type": "Question",
                  name: "Is Phantom open source?",
                  acceptedAnswer: {
                    "@type": "Answer",
                    text: "Yes. MIT licensed. Source at github.com/ashlrai/phantom-secrets. Rust workspace — phantom-core, phantom-vault, phantom-proxy, phantom-cli, phantom-mcp.",
                  },
                },
              ],
            }),
          }}
        />
      </head>
      <body className="bg-bg text-t1 antialiased min-h-svh">
        <PostHogProvider>{children}</PostHogProvider>
      </body>
    </html>
  );
}
