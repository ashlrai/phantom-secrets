import { isHostedServiceCommissioned } from "@/lib/commissioning";
import DashboardOverviewClient from "./overview-client";

export default function DashboardOverview() {
  if (!isHostedServiceCommissioned("personal_vaults")) {
    return (
      <section className="rounded-2xl border border-border bg-s1 p-8 text-center max-w-[720px]">
        <h2 className="text-[1.2rem] font-bold text-t1">
          Phantom Cloud is not commissioned
        </h2>
        <p className="mt-3 text-[0.9rem] text-t2 leading-[1.65] max-w-[560px] mx-auto">
          This deployment will not query or display personal vault metadata
          until the server-only cloud-vault gate is explicitly enabled. Local
          vaults, the proxy, and value-blind MCP workflows remain separate.
        </p>
      </section>
    );
  }

  return <DashboardOverviewClient />;
}
