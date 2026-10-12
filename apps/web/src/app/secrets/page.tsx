import type { Metadata } from "next";
import { CTA } from "@/components/landing/CTA";
import { Comparison } from "@/components/landing/Comparison";
import { DocumentationGateway } from "@/components/landing/DocumentationGateway";
import { Ecosystem } from "@/components/landing/Ecosystem";
import { EvidenceLedger } from "@/components/landing/EvidenceLedger";
import { FAQ } from "@/components/landing/FAQ";
import { Features } from "@/components/landing/Features";
import { Hero } from "@/components/landing/Hero";
import { Install } from "@/components/landing/Install";
import { LandingStructuredData } from "@/components/landing/LandingStructuredData";
import { Nav } from "@/components/landing/Nav";
import { Pricing } from "@/components/landing/Pricing";
import { QuickStart } from "@/components/landing/QuickStart";
import { RequestTrace } from "@/components/landing/RequestTrace";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { TrustBoundary } from "@/components/landing/TrustBoundary";
import { Transformation } from "@/components/landing/Transformation";

const title = "Phantom Secrets — API key security for AI coding agents";

export const metadata: Metadata = {
  title: { absolute: title },
  description: "Phantom Secrets is the local credential boundary for supported AI coding-agent workflows. Install the CLI, connect an MCP client and inspect the evidence behind exact-route credential injection.",
  alternates: { canonical: "https://phm.dev/secrets" },
  openGraph: {
    type: "website", siteName: "Phantom", url: "https://phm.dev/secrets",
    title: "Phantom Secrets — API key security for AI coding agents",
    description: "Keep provider credentials out of supported agent paths with a local vault, value-blind MCP tools and exact-route injection.",
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "Phantom Secrets keeps provider credentials behind a local boundary." }],
  },
  twitter: { card: "summary_large_image", title: "Phantom Secrets", description: "The local credential boundary in Phantom by AshlrAI.", images: ["/og-image.png"] },
};

export default function SecretsPage() {
  return (
    <>
      <Nav />
      <LandingStructuredData />
      <main id="main-content" tabIndex={-1} className="landing-shell elite-landing">
        <Hero />
        <Ecosystem />
        <Transformation />
        <RequestTrace />
        <QuickStart />
        <Install />
        <TrustBoundary />
        <Features />
        <Comparison />
        <DocumentationGateway />
        <EvidenceLedger />
        <Pricing />
        <FAQ />
        <CTA />
      </main>
      <SiteFooter />
    </>
  );
}
