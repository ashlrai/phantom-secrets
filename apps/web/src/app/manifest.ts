import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Phantom — API key security for AI coding agents",
    short_name: "Phantom",
    description:
      "Open-source CLI that gives supported AI workflows placeholders while an authenticated local proxy injects route-owned authentication only for exact configured HTTP routes.",
    start_url: "/",
    display: "standalone",
    background_color: "#050508",
    theme_color: "#050508",
    icons: [
      {
        src: "/favicon.svg",
        sizes: "any",
        type: "image/svg+xml",
      },
    ],
  };
}
