"use client";

import { useEffect, useRef, useState } from "react";
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
    "input" | "authenticating" | "approving" | "done" | "error"
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
        setStatus("error");
      }
    } catch {
      setError("Failed to connect. Please try again.");
      setStatus("error");
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

    const {
      data: { session },
    } = await getSupabase().auth.getSession();

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
        sessionStorage.removeItem("phantom_device_code");
        setError(authError.message);
        setStatus("input");
      }
      return;
    }

    await approveDevice(code, session.access_token);
  };

  const redirectHandled = useRef(false);
  useEffect(() => {
    if (redirectHandled.current) return;
    const params = new URLSearchParams(window.location.search);
    const isOAuthReturn = params.get("oauth") === "1";
    const storedCode = sessionStorage.getItem("phantom_device_code");

    if (isOAuthReturn) {
      redirectHandled.current = true;
      window.history.replaceState(null, "", "/device");
    }

    if (isOAuthReturn && storedCode) {
      setCode(storedCode);
      sessionStorage.removeItem("phantom_device_code");

      getSupabase().auth.getSession().then(({ data: { session } }) => {
        if (session) {
          approveDevice(storedCode, session.access_token);
        }
      });
    }
  }, []);

  return (
    <main className="min-h-screen bg-[#050508] text-[#f5f5f7] flex items-center justify-center p-6">
      <div className="max-w-md w-full text-center">
        <div className="flex items-center justify-center gap-2 mb-8">
          <span className="font-bold text-sm">Phantom</span>
        </div>

        {status === "done" ? (
          <div>
            <div className="w-16 h-16 bg-green-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg
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
            <p className="text-[#a1a1b5]">
              You can return to your terminal. The CLI will log you in
              automatically.
            </p>
            <a
              href="/dashboard"
              className="mt-6 inline-block rounded-lg bg-blue-600 hover:bg-blue-700 px-5 py-2.5 text-sm font-semibold text-white no-underline transition-colors"
            >
              Open your dashboard →
            </a>
          </div>
        ) : (
          <div>
            <h1 className="text-2xl font-bold mb-2">Authorize Device</h1>
            <p className="text-[#a1a1b5] mb-8">
              Enter the code shown in your terminal to authorize this device
              with Phantom Cloud.
            </p>

            <form onSubmit={handleSubmit} className="space-y-4">
              <input
                type="text"
                value={code}
                onChange={(event) => setCode(formatDeviceUserCode(event.target.value))}
                placeholder="XXXX-XXXX"
                className="w-full text-center text-3xl font-mono tracking-[0.3em] py-4 px-6 bg-[#0a0a12] border border-[#1a1a2c] rounded-lg text-[#f5f5f7] outline-none focus:border-blue-500 placeholder:text-[#333]"
                maxLength={9}
                autoFocus
                disabled={status !== "input"}
              />

              {error && <p className="text-red-400 text-sm">{error}</p>}

              <button
                type="submit"
                disabled={status !== "input" || code.length < 9}
                className="w-full py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-[#1a1a2c] disabled:text-[#65657a] rounded-lg font-semibold transition-colors"
              >
                {status === "authenticating"
                  ? "Signing in with GitHub..."
                  : status === "approving"
                    ? "Approving..."
                    : "Authorize Device"}
              </button>
            </form>

            <p className="text-[#65657a] text-xs mt-6">
              This will sign you in via GitHub and link this device to your
              Phantom account.
            </p>
          </div>
        )}
      </div>
    </main>
  );
}
