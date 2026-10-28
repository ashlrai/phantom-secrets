import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { getSecretUseCase, SECRET_USE_CASES, secretUseCasePath, type UseCaseClaim } from "@/lib/secret-use-cases";

interface UseCasePageProps {
  params: Promise<{ slug: string }>;
}

export const dynamicParams = false;

export function generateStaticParams() {
  return SECRET_USE_CASES.map(({ slug }) => ({ slug }));
}

export async function generateMetadata({ params }: UseCasePageProps): Promise<Metadata> {
  const { slug } = await params;
  const guide = getSecretUseCase(slug);
  if (!guide) notFound();
  const canonical = `https://phm.dev${secretUseCasePath(guide.slug)}`;
  const title = `${guide.title} | Phantom Secrets`;
  return {
    title: { absolute: title },
    description: guide.description,
    alternates: { canonical },
    openGraph: {
      type: "article", siteName: "Phantom", url: canonical, title,
      description: guide.description,
      images: [{ url: "https://phm.dev/og-image.png", width: 1200, height: 630, alt: "Phantom Secrets local credential boundary" }],
    },
    twitter: { card: "summary_large_image", title, description: guide.description, images: ["https://phm.dev/og-image.png"] },
  };
}

function Claim({ claim }: { claim: UseCaseClaim }) {
  return (
    <section id={claim.id} data-claim={claim.id} aria-labelledby={`${claim.id}-title`}>
      <h2 id={`${claim.id}-title`} className={claim.id === "fit" ? "!mt-0" : undefined}>{claim.title}</h2>
      {claim.paragraphs.map((paragraph) => <p key={paragraph}>{paragraph}</p>)}
      {claim.command && <pre tabIndex={0} aria-label={`${claim.title}: commands`}><code>{claim.command}</code></pre>}
      <ul aria-label={`Sources for ${claim.title}`} className="flex flex-wrap gap-x-5 gap-y-1 text-sm">
        {claim.sources.map((source) => (
          <li key={source.href}><Link data-source="true" href={source.href}>{source.label}</Link></li>
        ))}
      </ul>
    </section>
  );
}

export default async function UseCasePage({ params }: UseCasePageProps) {
  const { slug } = await params;
  const guide = getSecretUseCase(slug);
  if (!guide) notFound();
  const related = SECRET_USE_CASES.filter((entry) => entry.slug !== slug);
  const structuredData = {
    "@context": "https://schema.org", "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Phantom Secrets", item: "https://phm.dev/secrets" },
      { "@type": "ListItem", position: 2, name: guide.title, item: `https://phm.dev${secretUseCasePath(slug)}` },
    ],
  };

  return (
    <>
      <Nav />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData).replace(/</g, "\\u003c") }} />
      <main id="main-content" tabIndex={-1} className="docs-page docs-article-page">
        <header className="docs-page__hero">
          <div className="landing-frame">
            <nav aria-label="Breadcrumb" className="mb-6 flex flex-wrap gap-3 text-sm text-[var(--ink-soft)]">
              <Link href="/secrets">Phantom Secrets</Link><span aria-hidden="true">/</span><span>Use cases</span>
            </nav>
            <h1>{guide.title}</h1>
            <div className="mt-7 flex flex-wrap gap-4">
              <Link href="/secrets#install" className="inline-flex min-h-11 items-center rounded-lg bg-blue px-5 py-2.5 font-semibold text-white no-underline hover:bg-blue-d">Install Phantom Secrets</Link>
              <Link href="/docs/getting-started" className="inline-flex min-h-11 items-center px-2 text-[var(--verified-dark)] underline underline-offset-4">Read the setup guide</Link>
            </div>
          </div>
        </header>
        <div className="landing-frame docs-article-page__layout">
          <article className="docs-article">
            <Claim claim={guide.introduction} />
            {guide.steps.map((claim) => <Claim key={claim.id} claim={claim} />)}
            <Claim claim={guide.limits} />
          </article>
          <aside className="docs-article-page__aside" aria-label="Guide navigation">
            <h2 className="font-semibold">In this guide</h2>
            {[guide.introduction, ...guide.steps, guide.limits].map((claim) => <Link key={claim.id} href={`#${claim.id}`}>{claim.title}</Link>)}
            <h2 className="mt-10 font-semibold">Continue with another task</h2>
            {related.map((entry) => <Link key={entry.slug} href={secretUseCasePath(entry.slug)}>{entry.title}</Link>)}
            <Link href="/docs">Browse documentation</Link>
            <Link href="/secrets#install">Install Phantom Secrets</Link>
          </aside>
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
