import { isHostedServiceCommissioned } from "@/lib/commissioning";
import DeviceAuthorizationClient from "./device-authorization-client";

export default function DevicePage() {
  if (!isHostedServiceCommissioned("personal_vaults")) {
    return (
      <main className="min-h-screen bg-[#050508] text-[#f5f5f7] flex items-center justify-center p-6">
        <section className="max-w-md w-full text-center rounded-2xl border border-[#1a1a2c] bg-[#0a0a12] p-8">
          <p className="font-bold text-sm mb-8">Phantom</p>
          <h1 className="text-2xl font-bold mb-3">
            Cloud device sign-in is not commissioned
          </h1>
          <p className="text-[#a1a1b5] leading-relaxed">
            This deployment will not issue, approve, or exchange device codes
            until its server-only Phantom Cloud gate is explicitly enabled.
            Local vaults, the proxy, and value-blind MCP workflows remain
            available without hosted sign-in.
          </p>
          <a
            href="mailto:mason@ashlr.ai?subject=Phantom%20Cloud%20pilot%20interest"
            className="mt-6 inline-flex min-h-[44px] items-center rounded-lg border border-[#2a2a3c] px-4 py-2 text-sm font-semibold text-[#f5f5f7] no-underline transition-colors hover:border-[#65657a]"
          >
            Request pilot access
          </a>
        </section>
      </main>
    );
  }

  return <DeviceAuthorizationClient />;
}
