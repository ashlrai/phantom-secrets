import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { MarkdownDocument } from "@/components/docs/MarkdownDocument";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import {
  getPublicDoc,
  getPublicDocConfig,
  PUBLIC_DOCS,
} from "@/lib/public-docs";

interface PublicDocPageProps {
  params: Promise<{ slug: string }>;
}

export const dynamicParams = false;

export function generateStaticParams() {
  return PUBLIC_DOCS.map(({ slug }) => ({ slug }));
}

export async function generateMetadata({
  params,
}: PublicDocPageProps): Promise<Metadata> {
  const { slug } = await params;
  const doc = getPublicDocConfig(slug);
  if (!doc) return {};

  const canonical = `/docs/${doc.slug}`;
  const title = `${doc.title} — Phantom documentation`;

  return {
    title: doc.title,
    description: doc.description,
    alternates: { canonical },
    openGraph: {
      type: "article",
      siteName: "Phantom",
      title,
      description: doc.description,
      url: canonical,
      images: [
        {
          url: "/og-image.png",
          width: 1200,
          height: 630,
          alt: "Phantom open-source credential boundary for AI coding agents",
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description: doc.description,
      images: ["/og-image.png"],
    },
  };
}

export default async function PublicDocPage({ params }: PublicDocPageProps) {
  const { slug } = await params;
  const doc = getPublicDoc(slug);
  if (!doc) notFound();

  const canonicalUrl = `https://phm.dev/docs/${doc.slug}`;
  const structuredData = [
    {
      "@context": "https://schema.org",
      "@type": "TechArticle",
      headline: doc.title,
      description: doc.description,
      url: canonicalUrl,
      mainEntityOfPage: canonicalUrl,
      isPartOf: {
        "@type": "CollectionPage",
        name: "Phantom documentation",
        url: "https://phm.dev/docs",
      },
      author: {
        "@type": "Organization",
        name: "Ashlr AI",
        url: "https://ashlr.ai",
      },
      publisher: {
        "@type": "Organization",
        name: "Ashlr AI",
        url: "https://ashlr.ai",
      },
      license: "https://opensource.org/licenses/MIT",
      dateModified: doc.modified,
      sameAs: doc.sourceUrl,
    },
    {
      "@context": "https://schema.org",
      "@type": "BreadcrumbList",
      itemListElement: [
        {
          "@type": "ListItem",
          position: 1,
          name: "Documentation",
          item: "https://phm.dev/docs",
        },
        {
          "@type": "ListItem",
          position: 2,
          name: doc.title,
          item: canonicalUrl,
        },
      ],
    },
  ];
  const serializedStructuredData = JSON.stringify(structuredData).replace(
    /</g,
    "\\u003c",
  );

  return (
    <>
      <Nav />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: serializedStructuredData }}
      />
      <main id="main-content" tabIndex={-1} className="docs-page docs-article-page">
        <header className="docs-article-page__masthead">
          <div className="landing-frame docs-article-page__masthead-layout">
            <div>
              <p className="landing-kicker">Phantom documentation</p>
              <p className="docs-article-page__summary">{doc.description}</p>
            </div>
            <nav aria-label="Documentation breadcrumb" className="docs-article-page__breadcrumb">
              <Link href="/docs">Documentation</Link>
              <span aria-hidden="true">/</span>
              <span aria-current="page">{doc.title}</span>
            </nav>
          </div>
        </header>

        <div className="landing-frame docs-article-page__layout">
          <article className="docs-article">
            <MarkdownDocument markdown={doc.markdown} sourceFile={doc.file} />
          </article>

          <aside className="docs-article-page__aside" aria-label="Document source">
            <p className="landing-kicker">Canonical source</p>
            <p>
              This page is rendered from the repository Markdown at build time.
              Source can be ahead of the reviewed public release.
            </p>
            <p>Content last reviewed {doc.modified}.</p>
            <a href={doc.sourceUrl}>View {doc.file} on GitHub</a>
            <Link href="/docs">Browse all public guides</Link>
          </aside>
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
