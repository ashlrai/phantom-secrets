"use client";

import { useEffect, useState, type ReactNode } from "react";
import { usePathname } from "next/navigation";
import { getBrowserClient } from "@/lib/supabase-browser";
import { Nav } from "@/components/landing/Nav";
import { Github } from "@/components/landing/Icons";

type Status = "loading" | "signed_in" | "signed_out";

export default function DashboardLayout({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("loading");
  const [email, setEmail] = useState<string | null>(null);
  const [signingIn, setSigningIn] = useState(false);

  useEffect(() => {
    const supabase = getBrowserClient();
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (!session) {
        setStatus("signed_out");
        return;
      }
      setEmail(session.user.email ?? null);
      setStatus("signed_in");
    });
  }, []);

  const signIn = async () => {
    setSigningIn(true);
    const supabase = getBrowserClient();
    await supabase.auth.signInWithOAuth({
      provider: "github",
      options: {
        redirectTo: `${window.location.origin}${window.location.pathname}`,
      },
    });
  };

  if (status === "loading") {
    return (
      <>
        <Nav />
        <main className="mx-auto max-w-[1100px] px-7 pt-28 pb-20 text-center text-t3">
          Loading…
        </main>
      </>
    );
  }

  if (status === "signed_out") {
    return (
      <>
        <Nav />
        <main className="mx-auto max-w-[640px] px-7 pt-24 pb-20 text-center">
          <h1 className="text-[1.8rem] sm:text-[2.2rem] font-extrabold tracking-[-0.035em] text-white leading-[1.1]">
            Sign in to your dashboard
          </h1>
          <p className="mt-4 text-[0.95rem] text-t2 leading-[1.65]">
            View your cloud vaults, billing, and team membership. Same GitHub
            account you used with{" "}
            <code className="font-mono text-blue-b">phantom login</code>.
          </p>
          <button
            type="button"
            onClick={signIn}
            disabled={signingIn}
            className="mt-7 inline-flex items-center gap-2 rounded-lg bg-blue px-5 py-3 text-[0.92rem] font-semibold text-white transition-all hover:bg-blue-d hover:-translate-y-px hover:shadow-[0_4px_24px_rgba(59,130,246,0.32)] disabled:opacity-60 disabled:cursor-wait"
          >
            <Github className="h-4 w-4" />
            {signingIn ? "Redirecting to GitHub…" : "Sign in with GitHub"}
          </button>
          <p className="mt-5 text-[0.78rem] text-t3">
            We only request your GitHub login + email. No repo access.
          </p>
        </main>
      </>
    );
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-[1100px] px-7 pt-24 pb-20">
        <DashboardNav email={email} />
        <div className="mt-8">{children}</div>
      </main>
    </>
  );
}

function DashboardNav({ email }: { email: string | null }) {
  const pathname = usePathname();

  const links = [
    { href: "/dashboard", label: "Overview" },
    { href: "/dashboard/team", label: "Teams" },
    { href: "/dashboard/billing", label: "Billing" },
  ];

  return (
    <header className="flex flex-col gap-4 border-b border-border pb-6 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p className="text-[0.78rem] font-mono uppercase tracking-[0.16em] text-t3">
          Dashboard
        </p>
        <h1 className="mt-1 text-[1.6rem] sm:text-[2rem] font-extrabold tracking-[-0.035em] text-white leading-[1.1]">
          {email ? `Signed in as ${email}` : "Signed in"}
        </h1>
        <p className="mt-1 text-[0.85rem] text-t3">
          Read-only view of your projects, teams, and billing. Mutations
          stay in the CLI: <code className="font-mono text-blue-b">phantom</code>.
        </p>
      </div>
      <nav className="flex flex-wrap gap-1 rounded-lg border border-border bg-s1 p-1">
        {links.map((l) => {
          const active =
            l.href === "/dashboard"
              ? pathname === "/dashboard"
              : pathname.startsWith(l.href);
          return (
            <a
              key={l.href}
              href={l.href}
              className={
                "rounded-md px-3 py-1.5 text-[0.85rem] font-medium transition-colors " +
                (active
                  ? "bg-blue text-white"
                  : "text-t2 hover:bg-s2 hover:text-t1")
              }
            >
              {l.label}
            </a>
          );
        })}
      </nav>
    </header>
  );
}
