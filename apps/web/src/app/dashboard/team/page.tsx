import { isHostedServiceCommissioned } from "@/lib/commissioning";
import TeamPageClient from "./team-client";

export default function TeamPage() {
  if (!isHostedServiceCommissioned("teams")) {
    return (
      <section className="rounded-2xl border border-border bg-s1 p-8 text-center max-w-[720px]">
        <h2 className="text-[1.2rem] font-bold text-t1">
          Hosted teams are not commissioned
        </h2>
        <p className="mt-3 text-[0.9rem] text-t2 leading-[1.65] max-w-[560px] mx-auto">
          This deployment will not query membership, public-key, or team-vault
          metadata until the server-only team gate is explicitly enabled. The
          local source workflow remains separately testable.
        </p>
      </section>
    );
  }

  return <TeamPageClient />;
}
