"use client";

import { useEffect, useRef, useState } from "react";
import Image from "next/image";
import Link from "next/link";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import {
  formatDeviceUserCode,
  isValidDeviceUserCode,
  normalizeDeviceUserCode,
} from "@/lib/device-code";
import { capturePostHog } from "@/lib/posthog";

let supabase: SupabaseClient | null = null;
function getSupabase() {
  if (!supabase) {
    supabase = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
    );
  }
  return supabase;
}

export default function DeviceAuthorizationClient() {
  const [code, setCode] = useState("");
  const [status, setStatus] = useState<
    "input" | "authenticating" | "approving" | "done"
  >("input");
  const [error, setError] = useState("");

  const approveDevice = async (userCode: string, accessToken: string) => {
    setStatus("approving");
    try {
      const response = await fetch("/api/v1/auth/device/approve", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          user_code: normalizeDeviceUserCode(userCode),
        }),
      });

      if (response.ok) {
        setStatus("done");
        void capturePostHog("device_authorized");
      } else {
        const data = await response.json();
        setError(data.error || "Failed to approve device");
        setStatus("input");
      }
    } catch {
      setError("Failed to connect. Please try again.");
      setStatus("input");
    }
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!isValidDeviceUserCode(code)) {
      setError("Code must be 8 characters (XXXX-XXXX)");
      return;
    }

    setStatus("authenticating");
    setError("");

    try {
      const { data: { session }, error: sessionError } = await getSupabase().auth.getSession();
      if (sessionError) {
        setError("Unable to read your sign-in session. Please try again.");
        setStatus("input");
        return;
      }

      if (!session) {
        sessionStorage.setItem("phantom_device_code", code);
        const { error: authError } = await getSupabase().auth.signInWithOAuth({
          provider: "github",
          options: {
            // The one-time device code stays in tab-scoped session storage and never enters a
            // URL, referrer, provider callback, analytics event, or server log.
            redirectTo: `${window.location.origin}/device?oauth=1`,
          },
        });
        if (authError) {
          setError("GitHub sign-in could not start. Please try again.");
          setStatus("input");
        }
        return;
      }

      await approveDevice(code, session.access_token);
    } catch {
      setError("Unable to complete sign-in. Please try again.");
      setStatus("input");
    }
  };

  const redirectHandled = useRef(false);
  useEffect(() => {
    if (redirectHandled.current) return;
    const params = new URLSearchParams(window.location.search);
    const isOAuthReturn = params.get("oauth") === "1";
    if (!isOAuthReturn) return;
    let storedCode: string | null = null;
    try {
      storedCode = sessionStorage.getItem("phantom_device_code");
    } catch {
      // Restricted tab storage must not prevent the SDK consuming callback tokens.
    }

    // Guard before awaiting: development StrictMode must not approve twice.
    redirectHandled.current = true;
    if (storedCode) setCode(formatDeviceUserCode(storedCode));
    const callbackError = [params, new URLSearchParams(window.location.hash.slice(1))]
      .some((values) => ["error", "error_code", "error_description"].some((key) => values.has(key)));

    const completeOAuthReturn = async () => {
      setStatus("authenticating");
      let accessToken: string;
      try {
        const auth = getSupabase().auth;
        // Implicit OAuth tokens arrive in the URL fragment. The SDK must
        // consume it before our cleanup, and getSession alone hides errors
        // from initialization (potentially returning an older session).
        const { error: initializationError } = await auth.initialize();
        if (initializationError || callbackError) {
          setError("GitHub sign-in did not complete. Please try again.");
          setStatus("input");
          return;
        }
        const { data: { session }, error: sessionError } = await auth.getSession();
        if (sessionError || !session?.access_token) {
          setError("GitHub sign-in did not complete. Please try again.");
          setStatus("input");
          return;
        }
        accessToken = session.access_token;
      } catch {
        setError("Unable to complete sign-in. Please try again.");
        setStatus("input");
        return;
      } finally {
        // Clear callback data on success or failure, after SDK ingestion settles.
        window.history.replaceState(null, "", "/device");
      }

      if (!storedCode || !isValidDeviceUserCode(storedCode)) {
        setError("Sign-in completed. Enter the current code from your terminal to authorize this device.");
        setStatus("input");
        return;
      }
      try {
        sessionStorage.removeItem("phantom_device_code");
      } catch {
        // The restored code is already in component state for an explicit retry.
      }
      await approveDevice(storedCode, accessToken);
    };

    void completeOAuthReturn();
  }, []);

  const busy = status === "authenticating" || status === "approving";

  return (
    <main className="min-h-screen bg-bg text-t1 flex flex-col items-center justify-center px-4 py-10 sm:px-6">
      <div className="w-full max-w-md min-w-0">
        <Link href="/secrets" className="mb-8 flex min-h-[44px] items-center justify-center gap-3 text-t1 no-underline focus-visible:outline-2 focus-visible:outline-blue-b">
          <Image src="/favicon.svg" alt="" width={40} height={40} />
          <span className="text-lg font-semibold tracking-tight">Phantom Secrets</span>
        </Link>
        <section className="rounded-2xl border border-border bg-s1 p-5 text-center sm:p-8" aria-busy={busy}>

        {status === "done" ? (
          <div role="status">
            <div className="w-16 h-16 bg-green-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg
                aria-hidden="true"
                className="w-8 h-8 text-green-500"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M5 13l4 4L19 7"
                />
              </svg>
            </div>
            <h1 className="text-2xl font-bold mb-2">Device Authorized</h1>
            <p className="text-t2">
              You can return to your terminal. The CLI will log you in
              automatically.
            </p>
            <a
              href="/dashboard"
              className="mt-6 inline-flex min-h-[44px] items-center justify-center rounded-lg bg-blue-action hover:bg-blue-action-d px-5 py-2.5 text-sm font-semibold text-white no-underline transition-colors focus-visible:outline-2 focus-visible:outline-blue-b"
            >
              Open your dashboard
            </a>
          </div>
        ) : (
          <div>
            <h1 className="text-2xl font-bold mb-2">Authorize Device</h1>
            <p className="text-t2 mb-8">
              Enter the code shown in your terminal to authorize this device
              with Phantom Cloud.
            </p>

            <form onSubmit={handleSubmit} className="space-y-4">
              <label htmlFor="device-code" className="block text-left text-sm font-medium text-t1">
                Device code
              </label>
              <input
                id="device-code"
                name="device-code"
                type="text"
                autoComplete="off"
                autoCapitalize="characters"
                spellCheck={false}
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "device-error device-help" : "device-help"}
                value={code}
                onChange={(event) => setCode(formatDeviceUserCode(event.target.value))}
                placeholder="XXXX-XXXX"
                className="w-full min-w-0 text-center text-2xl sm:text-3xl font-mono tracking-[0.12em] sm:tracking-[0.2em] py-4 px-2 bg-bg border border-border-l rounded-lg text-t1 focus-visible:outline-2 focus-visible:outline-blue-b placeholder:text-t3"
                maxLength={9}
                autoFocus
                disabled={status !== "input"}
              />

              {error && <p id="device-error" role="alert" className="text-red-400 text-sm leading-relaxed">{error}</p>}

              <button
                type="submit"
                disabled={status !== "input" || code.length < 9}
                className="w-full min-h-[48px] py-3 bg-blue-action hover:bg-blue-action-d disabled:bg-s3 disabled:text-t3 rounded-lg font-semibold transition-colors focus-visible:outline-2 focus-visible:outline-blue-b"
              >
                {status === "authenticating"
                  ? "Signing in with GitHub..."
                  : status === "approving"
                    ? "Approving..."
                    : "Authorize Device"}
              </button>
            </form>

            <p role="status" className="sr-only">
              {busy ? status === "authenticating" ? "Signing in with GitHub." : "Approving your device." : ""}
            </p>
            <p id="device-help" className="text-t3 text-xs leading-relaxed mt-6">
              This will sign you in via GitHub and link this device to your
              Phantom account.
            </p>
          </div>
        )}
        </section>
        <Link href="/" className="mt-6 flex min-h-[44px] items-center justify-center text-sm text-t2 hover:text-t1 no-underline focus-visible:outline-2 focus-visible:outline-blue-b">
          Back to Phantom
        </Link>
      </div>
    </main>
  );
}
