import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import {
  PUBLIC_RELEASE_URL,
  PUBLIC_RELEASE_VERSION,
} from "@/lib/public-release";
import "./globals.css";
import { PostHogProvider } from "./providers";

// Self-hosted (see ./fonts/README.md) so the build never fetches from Google
// Fonts (vercel/next.js#99114). Same weights, style, display, latin
// unicode-range and CSS variables as the previous next/font/google setup.
// next/font requires literal options, so the latin range is repeated.
const sans = localFont({
  src: [
    { path: "./fonts/inter-tight/inter-tight-latin-400-normal.woff2", weight: "400", style: "normal" },
    { path: "./fonts/inter-tight/inter-tight-latin-500-normal.woff2", weight: "500", style: "normal" },
    { path: "./fonts/inter-tight/inter-tight-latin-600-normal.woff2", weight: "600", style: "normal" },
    { path: "./fonts/inter-tight/inter-tight-latin-700-normal.woff2", weight: "700", style: "normal" },
    { path: "./fonts/inter-tight/inter-tight-latin-800-normal.woff2", weight: "800", style: "normal" },
  ],
  variable: "--font-sans-stack",
  display: "swap",
  declarations: [{ prop: "unicode-range", value: "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD" }],
});

const mono = localFont({
  src: [
    { path: "./fonts/jetbrains-mono/jetbrains-mono-latin-400-normal.woff2", weight: "400", style: "normal" },
    { path: "./fonts/jetbrains-mono/jetbrains-mono-latin-500-normal.woff2", weight: "500", style: "normal" },
    { path: "./fonts/jetbrains-mono/jetbrains-mono-latin-600-normal.woff2", weight: "600", style: "normal" },
    { path: "./fonts/jetbrains-mono/jetbrains-mono-latin-700-normal.woff2", weight: "700", style: "normal" },
  ],
  variable: "--font-mono-stack",
  display: "swap",
  declarations: [{ prop: "unicode-range", value: "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD" }],
});

const SITE_URL = "https://phm.dev";
const TITLE = "Phantom — API key security for AI coding agents";
const DESCRIPTION =
  "Open-source, local-first credential boundary for AI coding agents. Managed dotenv values move to a local vault, and supported exact HTTP routes receive route-owned authentication.";

function serializeStructuredData(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: TITLE,
    template: "%s — Phantom",
  },
  description: DESCRIPTION,
  applicationName: "Phantom",
  authors: [{ name: "Ashlr AI", url: "https://ashlr.ai" }],
  creator: "Ashlr AI",
  publisher: "Ashlr AI",
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
    "AI agent security",
    "AI coding agents",
    "agentic engineering",
    "Claude Code secrets",
    "Cursor secrets",
    "Codex MCP server",
    "MCP secrets management",
    "secure API keys for AI",
    "phantom tokens",
    "vault",
  ],
  category: "developer tools",
  openGraph: {
    type: "website",
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
      "Supported AI workflows get placeholders. An authenticated local proxy injects route-owned authentication only for exact configured routes. Open-source CLI for Claude Code, Cursor, Windsurf, and Codex.",
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
  referrer: "origin-when-cross-origin",
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
            __html: serializeStructuredData({
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
                name: "Ashlr AI",
                url: "https://ashlr.ai",
              },
            }),
          }}
        />
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
                name: "Phantom",
                applicationCategory: "DeveloperApplication",
              },
            }),
          }}
        />
        {/* JSON-LD: Organization */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: serializeStructuredData({
              "@context": "https://schema.org",
              "@type": "Organization",
              name: "Ashlr AI",
              url: "https://ashlr.ai",
              sameAs: [
                "https://github.com/ashlrai",
                "https://github.com/ashlrai/phantom-secrets",
              ],
              brand: {
                "@type": "Brand",
                name: "Phantom",
                url: SITE_URL,
                logo: `${SITE_URL}/favicon.svg`,
              },
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
