import { CTA } from "@/components/landing/CTA";
import { Features } from "@/components/landing/Features";
import { Hero } from "@/components/landing/Hero";
import { HowItWorks } from "@/components/landing/HowItWorks";
import { Install } from "@/components/landing/Install";
import { Nav } from "@/components/landing/Nav";
import { Pricing } from "@/components/landing/Pricing";
import { QuickStart } from "@/components/landing/QuickStart";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { SupportedTools } from "@/components/landing/SupportedTools";
import { Transformation } from "@/components/landing/Transformation";

export default function Home() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <SupportedTools />
        <HowItWorks />
        <Transformation />
        <QuickStart />
        <Features />
        <Pricing />
        <Install />
        <CTA />
      </main>
      <SiteFooter />
    </>
  );
}
