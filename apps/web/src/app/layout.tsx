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
