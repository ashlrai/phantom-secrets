import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";
import { isHostedServiceCommissioned } from "@/lib/commissioning";
import DeviceAuthorizationClient from "./device-authorization-client";

// Commissioning is runtime configuration, including for credential-free builds.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Authorize your device | Phantom Secrets",
  description: "Sign in with GitHub to authorize your Phantom CLI device.",
  robots: { index: false, follow: false },
};

export default function DevicePage() {
  if (!isHostedServiceCommissioned("personal_vaults")) {
    return (
      <main className="min-h-screen bg-bg text-t1 flex flex-col items-center justify-center px-4 py-10 sm:px-6">
        <Link href="/secrets" className="mb-8 flex min-h-[44px] items-center justify-center gap-3 text-t1 no-underline focus-visible:outline-2 focus-visible:outline-blue-b">
          <Image src="/favicon.svg" alt="" width={40} height={40} />
          <span className="text-lg font-semibold tracking-tight">Phantom Secrets</span>
        </Link>
        <section className="max-w-md w-full min-w-0 text-center rounded-2xl border border-border bg-s1 p-5 sm:p-8">
          <h1 className="text-2xl font-bold mb-3">
            Cloud device sign-in is not commissioned
          </h1>
          <p className="text-t2 leading-relaxed">
            This deployment will not issue, approve, or exchange device codes
            until its server-only Phantom Cloud gate is explicitly enabled.
            Local vaults, the proxy, and value-blind MCP workflows remain
            available without hosted sign-in.
          </p>
          <a
            href="mailto:mason@ashlr.ai?subject=Phantom%20Cloud%20pilot%20interest"
            className="mt-6 inline-flex min-h-[44px] items-center rounded-lg border border-[#2a2a3c] px-4 py-2 text-sm font-semibold text-[#f5f5f7] no-underline transition-colors hover:border-blue-b focus-visible:outline-2 focus-visible:outline-blue-b"
          >
            Request pilot access
          </a>
        </section>
        <Link href="/" className="mt-6 flex min-h-[44px] items-center justify-center text-sm text-t2 hover:text-t1 no-underline focus-visible:outline-2 focus-visible:outline-blue-b">
          Back to Phantom
        </Link>
      </main>
    );
  }

  return <DeviceAuthorizationClient />;
}
