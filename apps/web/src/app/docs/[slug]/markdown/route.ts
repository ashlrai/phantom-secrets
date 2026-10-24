import { getPublicDoc, PUBLIC_DOCS } from "@/lib/public-docs";

export const dynamic = "force-static";
export const dynamicParams = false;

export function generateStaticParams() {
  return PUBLIC_DOCS.map(({ slug }) => ({ slug }));
}

export async function GET(_request: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const doc = getPublicDoc(slug);
  if (!doc) return new Response("Document not found", { status: 404 });
  return new Response(doc.markdown, {
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Link": `<https://phm.dev/docs/${doc.slug}>; rel="canonical"`,
    },
  });
}
