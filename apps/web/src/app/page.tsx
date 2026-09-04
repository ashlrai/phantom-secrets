import type { Metadata } from "next";
import { CTA } from "@/components/landing/CTA";
import { Comparison } from "@/components/landing/Comparison";
import { DocumentationGateway } from "@/components/landing/DocumentationGateway";
import { EvidenceLedger } from "@/components/landing/EvidenceLedger";
import { FAQ } from "@/components/landing/FAQ";
import { Features } from "@/components/landing/Features";
import { Hero } from "@/components/landing/Hero";
import { Install } from "@/components/landing/Install";
import { LandingStructuredData } from "@/components/landing/LandingStructuredData";
import { Nav } from "@/components/landing/Nav";
import { Pricing } from "@/components/landing/Pricing";
import { QuickStart } from "@/components/landing/QuickStart";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { TrustBoundary } from "@/components/landing/TrustBoundary";
import { Transformation } from "@/components/landing/Transformation";

export const metadata: Metadata = {
  alternates: { canonical: "/" },
  openGraph: {
    type: "website",
    siteName: "Phantom",
    title: "Phantom — API key security for AI coding agents",
    description: "Phantom helps keep provider values out of the managed dotenv and MCP path for Claude Code, Cursor, Windsurf, and Codex, with exact-route HTTP credential injection.",
    url: "/",
    locale: "en_US",
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "Phantom keeps a provider credential behind the local boundary while an AI workflow receives a placeholder." }],
  },
};

export default function Home() {
  return (
    <>
      <Nav />
      <LandingStructuredData />
      <main id="main-content" tabIndex={-1} className="landing-shell elite-landing">
        <Hero />
        <Transformation />
        <TrustBoundary />
        <Features />
        <Comparison />
        <QuickStart />
        <Install />
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
