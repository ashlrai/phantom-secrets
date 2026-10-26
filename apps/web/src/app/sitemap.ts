import type { MetadataRoute } from "next";
import { PUBLIC_DOCS } from "@/lib/public-docs";
import { gitLastModified } from "@/lib/git-last-modified";
import { SECRET_USE_CASES } from "@/lib/secret-use-cases";

const SITE_URL = "https://phm.dev";

const pages = [
  { path: "/", file: "src/app/page.tsx" },
  { path: "/secrets", file: "src/app/secrets/page.tsx" },
  { path: "/docs", file: "src/app/docs/page.tsx" },
  { path: "/pricing", file: "src/app/pricing/page.tsx" },
  { path: "/enterprise", file: "src/app/enterprise/page.tsx" },
  { path: "/government", file: "src/app/government/page.tsx" },
  { path: "/security", file: "src/app/security/page.tsx" },
] as const;

// Generate XML at build time, where Git is available, not in a serverless request.
export const dynamic = "force-static";

export default function sitemap(): MetadataRoute.Sitemap {
  const shared = ["src/app/layout.tsx", "src/components/landing", "src/app/globals.css"];
  const publicPages = pages.map(({ path, file }) => ({
    path,
    files: [file, ...shared],
  }));
  const documentationPages = PUBLIC_DOCS.map(({ slug, file }) => ({
    path: `/docs/${slug}`,
    files: [`../../docs/${file}`, "src/app/docs/[slug]/page.tsx", "src/components/docs/MarkdownDocument.tsx", ...shared],
  }));
  const useCasePages = SECRET_USE_CASES.map(({ slug }) => ({
    path: `/secrets/use-cases/${slug}`,
    files: ["src/lib/secret-use-cases.ts", "src/app/secrets/use-cases/[slug]/page.tsx", ...shared],
  }));

  return [...publicPages, ...documentationPages, ...useCasePages].map(({ path, files }) => ({
    url: new URL(path, SITE_URL).toString(),
    lastModified: gitLastModified(process.cwd(), files),
  }));
}
