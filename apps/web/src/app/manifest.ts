import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Phantom",
    short_name: "Phantom",
    description:
      "The engineering workbench for interactive agent sessions, autonomous fleet workflows and connected resources.",
    id: "/",
    start_url: "/",
    scope: "/",
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
