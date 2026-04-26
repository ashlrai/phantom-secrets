"use client";

import { useSupabaseQuery } from "@/lib/use-supabase-query";

type TeamMembership = {
  team_id: string;
  role: string;
  joined_at: string;
  team: { id: string; name: string; created_at: string } | null;
};

type TeamMember = {
  user_id: string;
  role: string;
  joined_at: string;
};

export default function TeamPage() {
  const { data: memberships, error } = useSupabaseQuery<TeamMembership[]>((sb) =>
    sb
      .from("team_members")
      .select("team_id, role, joined_at, team:teams(id, name, created_at)")
      .order("joined_at", { ascending: false })
  );

  if (error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-[0.92rem] text-red-300">
        {error}
      </div>
    );
  }

  if (memberships === null) {
    return <div className="text-[0.9rem] text-t3">Loading teams…</div>;
  }

  if (memberships.length === 0) {
    return (
      <section className="rounded-2xl border border-border bg-s1 p-8 text-center max-w-[640px]">
        <h2 className="text-[1.2rem] font-bold text-t1">No teams yet</h2>
        <p className="mt-3 text-[0.9rem] text-t2 leading-[1.65] max-w-[480px] mx-auto">
          Teams let multiple developers share the same encrypted vault. The
          server never sees plaintext — each member decrypts client-side from
          their own keypair. Pro tier required.
        </p>
        <div className="mt-5 inline-block rounded-lg bg-s2/60 px-4 py-3 text-left text-[0.82rem] font-mono text-t2">
          <span className="text-blue-b">$</span> phantom team create &quot;My team&quot;
          <br />
          <span className="text-blue-b">$</span> phantom team invite &lt;TEAM_ID&gt;
          &lt;github-username&gt;
        </div>
      </section>
    );
  }

  return (
    <div className="grid gap-6">
      {memberships.map((m) => (
        <TeamCard key={m.team_id} membership={m} />
      ))}
      <section className="rounded-xl border border-border bg-s1 px-5 py-4 text-[0.85rem] text-t2 leading-[1.65] max-w-[760px]">
        Mutations stay in the CLI for now:{" "}
        <code className="font-mono text-blue-b">phantom team create</code>,{" "}
        <code className="font-mono text-blue-b">phantom team invite</code>,{" "}
        <code className="font-mono text-blue-b">phantom team members</code>.
      </section>
    </div>
  );
}

function TeamCard({ membership }: { membership: TeamMembership }) {
  const { data: members } = useSupabaseQuery<TeamMember[]>(
    (sb) =>
      sb
        .from("team_members")
        .select("user_id, role, joined_at")
        .eq("team_id", membership.team_id)
        .order("joined_at", { ascending: true }),
    [membership.team_id]
  );

  return (
    <section className="rounded-2xl border border-border bg-s1 overflow-hidden">
      <div className="flex flex-col gap-1 border-b border-border px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-[1.05rem] font-bold text-t1">
            {membership.team?.name ?? "Unnamed team"}
          </h2>
          <p className="mt-1 text-[0.78rem] font-mono text-t3">
            {membership.team_id}
          </p>
        </div>
        <span className="inline-flex items-center rounded-full border border-border bg-s2 px-2.5 py-0.5 text-[0.72rem] font-mono uppercase tracking-[0.08em] text-t2 w-fit">
          {membership.role}
        </span>
      </div>

      <div className="px-5 py-4">
        <p className="text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
          Members
        </p>
        {members === null ? (
          <p className="mt-2 text-[0.85rem] text-t3">Loading members…</p>
        ) : (
          <ul className="mt-3 grid gap-2">
            {members.map((m) => (
              <li
                key={m.user_id}
                className="flex items-center justify-between text-[0.86rem] text-t2"
              >
                <span className="font-mono truncate">{m.user_id}</span>
                <span className="text-[0.72rem] font-mono uppercase tracking-[0.08em] text-t3">
                  {m.role}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
