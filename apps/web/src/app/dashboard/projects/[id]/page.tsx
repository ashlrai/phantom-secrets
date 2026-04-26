"use client";

import { useParams } from "next/navigation";
import { useSupabaseQuery } from "@/lib/use-supabase-query";

type VaultRow = {
  project_id: string;
  version: number;
  updated_at: string;
  created_at: string;
  encrypted_blob: string;
};

export default function ProjectDetail() {
  const params = useParams<{ id: string }>();
  const projectId = decodeURIComponent(params.id);
  const { data: vault, error, loading } = useSupabaseQuery<VaultRow | null>(
    (sb) =>
      sb
        .from("vault_blobs")
        .select("project_id, version, updated_at, created_at, encrypted_blob")
        .eq("project_id", projectId)
        .maybeSingle(),
    [projectId]
  );

  if (error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4 text-[0.92rem] text-red-300">
        {error}
      </div>
    );
  }

  if (loading) {
    return <div className="text-[0.9rem] text-t3">Loading project…</div>;
  }

  if (!vault) {
    return (
      <div className="rounded-2xl border border-border bg-s1 p-8 text-center">
        <p className="text-[1rem] font-bold text-t1">Project not found</p>
        <p className="mt-2 text-[0.88rem] text-t3">
          We couldn&apos;t find a cloud vault for{" "}
          <code className="font-mono text-blue-b">{projectId}</code> on your
          account.
        </p>
        <a
          href="/dashboard"
          className="mt-5 inline-flex rounded-lg border border-border-l px-4 py-2 text-[0.85rem] font-semibold text-t1 no-underline hover:border-t3"
        >
          ← Back to overview
        </a>
      </div>
    );
  }

  const sizeKb = Math.round((vault.encrypted_blob.length * 3) / 4 / 102.4) / 10;

  return (
    <div className="grid gap-6">
      <a
        href="/dashboard"
        className="text-[0.82rem] text-t3 hover:text-t1 no-underline w-fit"
      >
        ← All projects
      </a>

      <section className="rounded-2xl border border-border bg-s1 p-6">
        <p className="text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
          Project
        </p>
        <h2 className="mt-1 text-[1.4rem] font-extrabold tracking-[-0.03em] text-white font-mono break-all">
          {vault.project_id}
        </h2>

        <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Field label="Version" value={`v${vault.version}`} />
          <Field label="Size" value={`${sizeKb.toFixed(1)} kB`} />
          <Field label="First synced" value={new Date(vault.created_at).toLocaleDateString()} />
          <Field label="Last synced" value={new Date(vault.updated_at).toLocaleString()} />
        </div>
      </section>

      <section className="rounded-2xl border border-border bg-s1 p-6">
        <h3 className="text-[1rem] font-bold text-t1 flex items-center gap-2">
          <LockIcon /> Vault contents
        </h3>
        <p className="mt-3 text-[0.88rem] text-t2 leading-[1.7] max-w-[640px]">
          The vault is end-to-end encrypted with{" "}
          <code className="font-mono text-blue-b">ChaCha20-Poly1305</code> and{" "}
          <code className="font-mono text-blue-b">Argon2id</code>. Only your
          local CLI holds the passphrase. We never see plaintext — and{" "}
          neither does this dashboard. To inspect or modify secrets in this
          project:
        </p>
        <ul className="mt-4 grid gap-2 text-[0.86rem] text-t2">
          <li>
            <code className="font-mono text-blue-b">phantom list</code> — show
            secret names (still no values)
          </li>
          <li>
            <code className="font-mono text-blue-b">phantom reveal &lt;KEY&gt;</code>{" "}
            — print one secret value
          </li>
          <li>
            <code className="font-mono text-blue-b">phantom rotate</code> —
            regenerate all phantom tokens (real keys unchanged)
          </li>
          <li>
            <code className="font-mono text-blue-b">phantom cloud pull</code>{" "}
            — download the latest version into your local vault
          </li>
        </ul>
      </section>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[0.72rem] font-mono uppercase tracking-[0.1em] text-t3">
        {label}
      </p>
      <p className="mt-1 text-[0.88rem] text-t1 font-medium">{value}</p>
    </div>
  );
}

function LockIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="text-blue-b"
      aria-hidden
    >
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}
