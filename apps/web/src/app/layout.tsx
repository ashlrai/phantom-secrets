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
const TITLE = "Phantom — Delegate everything to AI";
const DESCRIPTION =
  "Phantom hands AI a worthless token and injects the real API key at the network layer. Full access. Zero exposure. Works with Claude Code, Cursor, Windsurf, and Codex.";

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
        alt: "Phantom — the blue ghost cradles your real API key (amber star) while handing AI a worthless phm_a8f2c4d9 phantom token.",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    site: "@ashlrai",
    creator: "@ashlrai",
    title: TITLE,
    description:
      "AI gets a phantom. Real keys never leave your machine. Open-source CLI for Claude Code, Cursor, Windsurf, Codex.",
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
        <link rel="alternate" type="application/json" href="/.well-known/ai-plugin.json" title="Phantom AI plugin manifest" />

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
              softwareVersion: "0.5",
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
                "Set up Phantom so your AI coding tools never see real API keys.",
              totalTime: "PT1M",
              tool: [
                { "@type": "HowToTool", name: "Node.js (for npx)" },
                { "@type": "HowToTool", name: "Claude Code, Cursor, Windsurf, or Codex" },
              ],
              step: [
                {
                  "@type": "HowToStep",
                  name: "Install Phantom and protect your .env",
                  text: "Run `npx phantom-secrets init` in your project root. Phantom auto-detects API keys, moves them to your OS keychain, and rewrites the .env with phm_ tokens.",
                },
                {
                  "@type": "HowToStep",
                  name: "Register the MCP server with your editor",
                  text: "Run `claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp` for Claude Code, or paste the JSON into Cursor / Windsurf MCP settings.",
                },
                {
                  "@type": "HowToStep",
                  name: "Run your code with the proxy injecting real keys",
                  text: "Use `phantom exec -- <command>` to start a process whose API calls go through the local proxy. The proxy swaps phm_ tokens for real keys at the network layer.",
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
                    text: "About 0.5 ms of proxy overhead per request — not measurable in practice. The proxy is a Rust HTTP server bound to 127.0.0.1.",
                  },
                },
                {
                  "@type": "Question",
                  name: "What does AI see when Phantom is installed?",
                  acceptedAnswer: {
                    "@type": "Answer",
                    text: "The .env file contains phm_xxxxxxxx tokens instead of real values. AI tools read those tokens. The local proxy swaps them for real keys just before the outbound TLS connection.",
                  },
                },
                {
                  "@type": "Question",
                  name: "What happens if a phm_ token leaks from AI logs?",
                  acceptedAnswer: {
                    "@type": "Answer",
                    text: "Nothing. phm_ tokens are session-scoped placeholders that have no value outside your local proxy. The real key never left your machine.",
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
                    text: "Claude Code, Cursor, Windsurf, Codex via MCP. Any tool that reads .env files works automatically because Phantom rewrites the file.",
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
