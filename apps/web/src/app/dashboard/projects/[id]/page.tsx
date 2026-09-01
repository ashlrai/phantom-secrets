import { isHostedServiceCommissioned } from "@/lib/commissioning";
import ProjectDetailClient from "./project-client";

export default function ProjectDetail() {
  if (!isHostedServiceCommissioned("personal_vaults")) {
    return (
      <section className="rounded-2xl border border-border bg-s1 p-8 text-center max-w-[720px]">
        <h2 className="text-[1.2rem] font-bold text-t1">
          Project metadata is unavailable
        </h2>
        <p className="mt-3 text-[0.9rem] text-t2 leading-[1.65] max-w-[560px] mx-auto">
          Personal cloud vaults are not commissioned on this deployment, so
          no hosted project lookup was attempted.
        </p>
        <a
          href="/dashboard"
          className="mt-5 inline-flex rounded-lg border border-border-l px-4 py-2 text-[0.85rem] font-semibold text-t1 no-underline hover:border-t3"
        >
          ← Back to overview
        </a>
      </section>
    );
  }

  return <ProjectDetailClient />;
}
