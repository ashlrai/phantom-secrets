import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Phantom — Delegate everything to AI",
  description:
    "Let AI agents use your API keys without the security risk. Phantom replaces real secrets with worthless tokens and injects credentials at the network layer.",
  metadataBase: new URL("https://phm.dev"),
  openGraph: {
    title: "Phantom — Delegate everything to AI",
    description:
      "Let AI agents use your API keys without the security risk. All the convenience of pasting secrets into Claude. None of the leaks.",
    url: "https://phm.dev",
    images: ["/og-image.png"],
    siteName: "Phantom",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Phantom — Delegate everything to AI",
    description:
      "Let AI agents use your API keys without the security risk. Open-source CLI.",
    images: ["/og-image.png"],
  },
  icons: { icon: "/favicon.svg" },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <meta name="theme-color" content="#3b82f6" />
        <link rel="canonical" href="https://phm.dev/" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap"
          rel="stylesheet"
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "SoftwareApplication",
              name: "Phantom",
              description:
                "Open-source CLI that prevents AI coding agents from leaking your API keys",
              url: "https://github.com/ashlrai/phantom-secrets",
              applicationCategory: "DeveloperApplication",
              operatingSystem: "macOS, Linux",
              license: "https://opensource.org/licenses/MIT",
              offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
              author: {
                "@type": "Organization",
                name: "Ashlar AI",
                url: "https://ashlar.ai",
              },
            }),
          }}
        />
      </head>
      <body
        className="bg-[#050508] text-[#f5f5f7] antialiased"
        style={{ fontFamily: "'Inter', system-ui, sans-serif" }}
      >
        {children}
      </body>
    </html>
  );
}
