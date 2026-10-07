import type { Metadata } from "next";
import { Nav } from "@/components/landing/Nav";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { WorkbenchHero } from "@/components/landing/WorkbenchHero";
import { PhantomWorldScene } from "@/components/landing/PhantomWorldScene";
import { WorkbenchIntegrations } from "@/components/landing/WorkbenchIntegrations";

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
  return <><Nav /><main id="main-content" tabIndex={-1} className="phantom-workbench-surface">
    <WorkbenchHero />
    <div className="phantom-home-content">
      <PhantomWorldScene />
      <WorkbenchIntegrations />
      <section id="phantom-secrets" className="phantom-secrets-bridge" aria-labelledby="secrets-bridge-title">
        <h2 id="secrets-bridge-title">Phantom Secrets. A boundary for your credentials.</h2>
        <p>The local-first Secrets CLI and MCP server keep real API keys out of supported agent paths. See its installation, client setup and reviewed release evidence on the dedicated product page.</p>
        <a href="/secrets">Explore Phantom Secrets →</a>
        <p>Looking for an existing Secrets section?</p>
        <div className="phantom-workbench__actions">
          <a id="how" href="/secrets#how">How it works</a>
          <a id="features" href="/secrets#features">Secrets features</a>
          <a id="install" href="/secrets#install">Install Secrets</a>
          <a id="connect" href="/secrets#connect">Connect a client</a>
          <a id="comparison" href="/secrets#comparison">Compare the credential boundary</a>
          <a id="pricing" href="/secrets#pricing">Secrets pricing</a>
          <a id="faq" href="/secrets#faq">Secrets questions</a>
        </div>
      </section>
    </div>
  </main><SiteFooter /></>;
}
