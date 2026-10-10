"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { getBrowserClient } from "@/lib/supabase-browser";
import { Nav } from "@/components/landing/Nav";
import { Github } from "@/components/landing/Icons";

type Status = "loading" | "signed_in" | "signed_out" | "unavailable";

export default function DashboardLayout({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("loading");
  const [email, setEmail] = useState<string | null>(null);
  const [signingIn, setSigningIn] = useState(false);

  useEffect(() => {
    let active = true;
    const params = new URLSearchParams(window.location.search);
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const callbackError = [params, fragment].some((values) =>
      ["error", "error_code", "error_description"].some((key) => values.has(key))
    );
    // Also recognize callbacks started before the explicit return marker was added.
    const isOAuthReturn = params.get("oauth") === "1" || callbackError ||
      params.has("code") || fragment.has("access_token") || fragment.has("refresh_token");

    const loadSession = async () => {
      try {
        const supabase = getBrowserClient();
        // getSession waits for initialization but discards its error, which can
        // otherwise let a previous session hide a failed OAuth callback.
        const { error: initializationError } = await supabase.auth.initialize();
        if (!active) return;
        if (initializationError || callbackError) {
          setStatus("unavailable");
          return;
        }
        const { data: { session }, error } = await supabase.auth.getSession();
        if (!active) return;
        if (error) {
          setStatus("unavailable");
        } else if (!session) {
          setStatus("signed_out");
        } else {
          setEmail(session.user.email ?? null);
          setStatus("signed_in");
        }
      } catch {
        if (active) setStatus("unavailable");
      } finally {
        // Let the SDK ingest the callback first. Do not let a stale effect
        // rewrite the URL after navigation or StrictMode cleanup.
        if (active && isOAuthReturn) {
          window.history.replaceState(null, "", window.location.pathname);
        }
      }
    };

    void loadSession();
    return () => {
      active = false;
    };
  }, []);

  const signIn = async () => {
    setSigningIn(true);
    try {
      const supabase = getBrowserClient();
      const { error } = await supabase.auth.signInWithOAuth({
        provider: "github",
        options: {
          redirectTo: `${window.location.origin}${window.location.pathname}?oauth=1`,
        },
      });
      if (error) throw error;
    } catch {
      setStatus("unavailable");
      setSigningIn(false);
    }
  };

  if (status === "loading") {
    return (
      <>
        <Nav />
        <main className="mx-auto max-w-[1100px] px-7 pt-28 pb-20 text-center text-t3">
          Checking session…
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
            Sign in with GitHub to view your account and encrypted personal
            backup when cloud backups are enabled on this deployment. Team
            sharing and paid plans are not available.
          </p>
          <button
            type="button"
            onClick={signIn}
            disabled={signingIn}
            className="mt-7 inline-flex items-center gap-2 rounded-lg bg-blue-action px-5 py-3 text-[0.92rem] font-semibold text-white transition-all hover:bg-blue-action-d hover:-translate-y-px hover:shadow-[0_4px_24px_rgba(59,130,246,0.32)] disabled:opacity-60 disabled:cursor-wait"
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

  if (status === "unavailable") {
    return (
      <>
        <Nav />
        <main className="mx-auto max-w-[640px] px-7 pb-20 pt-24 text-center">
          <p className="font-mono text-[0.72rem] uppercase tracking-[0.16em] text-blue-b">
            Sign-in did not complete
          </p>
          <h1 className="mt-4 text-[1.8rem] font-extrabold leading-[1.1] tracking-[-0.035em] text-white sm:text-[2.2rem]">
            Try signing in again.
          </h1>
          <p role="alert" className="mt-4 text-[0.95rem] leading-[1.65] text-t2">
            We could not complete GitHub sign-in. Please try again. Phantom
            Secrets&apos; local CLI remains available.
          </p>
          <button
            type="button"
            onClick={signIn}
            disabled={signingIn}
            className="mt-7 inline-flex min-h-11 items-center gap-2 rounded-lg bg-blue-action px-5 py-3 text-[0.92rem] font-semibold text-white transition-colors hover:bg-blue-action-d disabled:cursor-wait disabled:opacity-60 focus-visible:outline-2 focus-visible:outline-blue-b"
          >
            <Github aria-hidden className="h-4 w-4" />
            {signingIn ? "Redirecting to GitHub…" : "Try GitHub sign-in again"}
          </button>
          <Link
            href="/"
            className="mt-7 inline-flex min-h-11 items-center justify-center rounded-lg border border-border-l px-5 py-3 text-[0.9rem] font-semibold text-t1 no-underline transition hover:border-t3"
          >
            Return to the open-source project
          </Link>
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
          Your account and encrypted backup metadata. Personal backups require
          cloud access on this deployment; team sharing and paid plans are not
          available.
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
                  ? "bg-blue-action text-white"
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
