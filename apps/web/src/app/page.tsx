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
import { WorkbenchHero } from "@/components/landing/WorkbenchHero";

export const metadata: Metadata = {
  title: { absolute: "Phantom — Engineering agents, together" },
  description: "Phantom by AshlrAI brings interactive engineering sessions, autonomous fleet workflows and a local credential boundary into one ecosystem. Explore the workbench and Phantom Secrets.",
  alternates: { canonical: "/" },
  openGraph: {
    type: "website",
    siteName: "Phantom",
    title: "Phantom — Engineering agents, together",
    description: "Explore the Phantom engineering workbench and Phantom Secrets, the local credential boundary for supported coding-agent workflows.",
    url: "/",
    locale: "en_US",
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "Phantom keeps a provider credential behind the local boundary while an AI workflow receives a placeholder." }],
  },
  twitter: {
    card: "summary_large_image",
    title: "Phantom — Engineering agents, together",
    description: "Work with your agents or steer an engineering fleet. Explore the workbench and Phantom Secrets by AshlrAI.",
    images: ["/og-image.png"],
  },
};

export default function Home() {
  return (
    <>
      <Nav />
      <LandingStructuredData />
      <main id="main-content" tabIndex={-1} className="landing-shell elite-landing">
        <div className="phantom-workbench-surface">
          <WorkbenchHero />
        </div>
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
