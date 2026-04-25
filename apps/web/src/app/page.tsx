import { Comparison } from "@/components/landing/Comparison";
import { CTA } from "@/components/landing/CTA";
import { FAQ } from "@/components/landing/FAQ";
import { FeatureGrid } from "@/components/landing/FeatureGrid";
import { Hero } from "@/components/landing/Hero";
import { HowItWorks } from "@/components/landing/HowItWorks";
import { Install } from "@/components/landing/Install";
import { Nav } from "@/components/landing/Nav";
import { ProblemBand } from "@/components/landing/ProblemBand";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { SupportedTools } from "@/components/landing/SupportedTools";
import { TerminalDemo } from "@/components/landing/TerminalDemo";
import { Trust } from "@/components/landing/Trust";
import { UseCases } from "@/components/landing/UseCases";

export default function Home() {
  return (
    <>
      <Nav />
      <main className="grain">
        <Hero />
        <SupportedTools />
        <HowItWorks />
        <Comparison />
        <ProblemBand />
        <UseCases />
        <TerminalDemo />
        <FeatureGrid />
        <Install />
        <FAQ />
        <Trust />
        <CTA />
      </main>
      <SiteFooter />
    </>
  );
}
