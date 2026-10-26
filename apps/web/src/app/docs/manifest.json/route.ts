import { PUBLIC_DOCS } from "@/lib/public-docs";
import { WORKBENCH_RELEASE } from "@/lib/workbench-release";

export const dynamic = "force-static";

export function GET() {
  return Response.json({
    schemaVersion: 1,
    site: "https://phm.dev",
    documentationReviewed: "2026-10-13",
    workbenchDocumentationSource: "37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05",
    publishedWorkbenchRelease: WORKBENCH_RELEASE,
    runtimeReadiness: "Inspect the user's installed CLI; public documentation does not establish live readiness.",
    agentReferences: {
      compact: "https://phm.dev/workbench/llms.txt",
      full: "https://phm.dev/workbench/llms-full.txt",
      secrets: "https://phm.dev/llms-full.txt",
    },
    documents: PUBLIC_DOCS.map(({ slug, title, description, modified }) => ({
      slug, title, description, modified,
      product: slug === "workbench" || slug.startsWith("workbench-") ? "workbench" : "secrets",
      url: `https://phm.dev/docs/${slug}`,
      markdownUrl: `https://phm.dev/docs/${slug}/markdown`,
    })),
  }, { headers: { "Link": '<https://phm.dev/docs>; rel="canonical"' } });
}
