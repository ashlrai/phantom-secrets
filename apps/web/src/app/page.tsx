import type { Metadata } from "next";
import { CTA } from "@/components/landing/CTA";
import { DocumentationGateway } from "@/components/landing/DocumentationGateway";
import { Ecosystem } from "@/components/landing/Ecosystem";
import { EvidenceLedger } from "@/components/landing/EvidenceLedger";
import { FAQ } from "@/components/landing/FAQ";
import { Features } from "@/components/landing/Features";
import { Hero } from "@/components/landing/Hero";
import { Install } from "@/components/landing/Install";
import { Nav } from "@/components/landing/Nav";
import { Pricing } from "@/components/landing/Pricing";
import { QuickStart } from "@/components/landing/QuickStart";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { TrustBoundary } from "@/components/landing/TrustBoundary";
import { Transformation } from "@/components/landing/Transformation";

export const metadata: Metadata = {
  alternates: { canonical: "/" },
  openGraph: { url: "/" },
};

export default function Home() {
  return (
    <>
      <Nav />
      <main id="main-content" tabIndex={-1} className="landing-shell">
        <Hero />
        <Ecosystem />
        <Transformation />
        <TrustBoundary />
        <Features />
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
