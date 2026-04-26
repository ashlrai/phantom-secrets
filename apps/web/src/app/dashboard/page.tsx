"use client";

import { useSupabaseQuery } from "@/lib/use-supabase-query";

type VaultRow = {
  project_id: string;
  version: number;
  updated_at: string;
  encrypted_blob: string;
};

type UserRow = {
  github_login: string;
  email: string | null;
  plan: string;
};

function bytesToKb(s: string) {
  // Encrypted blob is base64. Approximate ciphertext size: len * 3/4.
  return Math.round((s.length * 3) / 4 / 102.4) / 10;
}

function relTime(iso: string) {
  const d = new Date(iso);
  const ms = Date.now() - d.getTime();
  const m = Math.round(ms / 60_000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const days = Math.round(h / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

export default function DashboardOverview() {
  const { data: user, error: userError } = useSupabaseQuery<UserRow>((sb) =>
    sb.from("users").select("github_login, email, plan").single()
  );
  const { data: vaults, error: vaultsError } = useSupabaseQuery<VaultRow[]>((sb) =>
    sb
      .from("vault_blobs")
      .select("project_id, version, updated_at, encrypted_blob")
      .order("updated_at", { ascending: false })
  );
  const error = userError ?? vaultsError;

  if (error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-[0.92rem] text-red-300">
        {error}
      </div>
    );
  }

  if (!user || vaults === null) {
    return <div className="text-[0.9rem] text-t3">Loading your data…</div>;
  }

  return (
    <div className="grid gap-6">
      <section className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard label="Plan" value={user.plan === "pro" ? "Pro" : "Free"} hint={user.plan === "pro" ? "$8/mo" : "0/mo"} />
        <StatCard label="Cloud vaults" value={String(vaults.length)} hint={user.plan === "pro" ? "unlimited" : `${vaults.length}/1 free tier`} />
        <StatCard
          label="Total ciphertext"
          value={`${vaults.reduce((s, v) => s + bytesToKb(v.encrypted_blob), 0).toFixed(1)} kB`}
          hint="end-to-end encrypted"
        />
      </section>

      <section className="rounded-2xl border border-border bg-s1 overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <h2 className="text-[0.95rem] font-bold text-t1">Your projects</h2>
          <span className="text-[0.78rem] text-t3 font-mono">
            {vaults.length} {vaults.length === 1 ? "project" : "projects"}
          </span>
        </div>
        {vaults.length === 0 ? (
          <div className="px-5 py-10 text-center text-[0.88rem] text-t3">
            No cloud vaults yet. Run{" "}
            <code className="font-mono text-blue-b">phantom cloud push</code>{" "}
            from a project to upload an encrypted backup.
          </div>
        ) : (
          <table className="w-full text-left">
            <thead className="bg-s2/40">
              <tr>
                <th className="px-5 py-3 text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
                  Project ID
                </th>
                <th className="px-5 py-3 text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
                  Version
                </th>
                <th className="px-5 py-3 text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
                  Size
                </th>
                <th className="px-5 py-3 text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
                  Last sync
                </th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody>
              {vaults.map((v, i) => (
                <tr
                  key={v.project_id}
                  className={i === vaults.length - 1 ? "" : "border-b border-border"}
                >
                  <td className="px-5 py-3 text-[0.86rem] text-t1 font-mono truncate max-w-[280px]">
                    {v.project_id}
                  </td>
                  <td className="px-5 py-3 text-[0.86rem] text-t2">v{v.version}</td>
                  <td className="px-5 py-3 text-[0.86rem] text-t2">
                    {bytesToKb(v.encrypted_blob).toFixed(1)} kB
                  </td>
                  <td className="px-5 py-3 text-[0.86rem] text-t2">
                    {relTime(v.updated_at)}
                  </td>
                  <td className="px-5 py-3 text-right">
                    <a
                      href={`/dashboard/projects/${encodeURIComponent(v.project_id)}`}
                      className="text-[0.84rem] font-medium text-blue-b hover:text-blue no-underline"
                    >
                      View →
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

function StatCard({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="rounded-xl border border-border bg-s1 px-5 py-4">
      <p className="text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
        {label}
      </p>
      <p className="mt-2 text-[1.6rem] font-extrabold tracking-[-0.03em] text-white leading-none">
        {value}
      </p>
      <p className="mt-1 text-[0.78rem] text-t3">{hint}</p>
    </div>
  );
}
