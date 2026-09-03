import type { Metadata } from "next";
import { CTA } from "@/components/landing/CTA";
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
        <TrustBoundary />
        <Features />
        <QuickStart />
        <Install />
        <EvidenceLedger />
        <Pricing />
        <FAQ />
        <CTA />
      </main>
      <SiteFooter />
    </>
  );
}
