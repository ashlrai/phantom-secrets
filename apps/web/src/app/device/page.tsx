"use client";

import { useState, useEffect, useRef } from "react";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

let _supabase: SupabaseClient | null = null;
function getSupabase() {
  if (!_supabase) {
    _supabase = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
    );
  }
  return _supabase;
}

export default function DevicePage() {
  const [code, setCode] = useState("");
  const [status, setStatus] = useState<
    "input" | "authenticating" | "approving" | "done" | "error"
  >("input");
  const [error, setError] = useState("");

  const formatCode = (val: string) => {
    const clean = val.replace(/[^A-Za-z0-9]/g, "").toUpperCase().slice(0, 8);
    if (clean.length > 4) {
      return clean.slice(0, 4) + "-" + clean.slice(4);
    }
    return clean;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanCode = code.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
    if (cleanCode.length !== 8) {
      setError("Code must be 8 characters (XXXX-XXXX)");
      return;
    }

    setStatus("authenticating");
    setError("");

    // Check if user is already signed in
    const {
      data: { session },
    } = await getSupabase().auth.getSession();

    if (!session) {
      // Redirect to GitHub OAuth, storing the code for after auth
      localStorage.setItem("phantom_device_code", code);
      const { error: authError } = await getSupabase().auth.signInWithOAuth({
        provider: "github",
        options: {
          redirectTo: `${window.location.origin}/device?code=${encodeURIComponent(code)}`,
        },
      });
      if (authError) {
        setError(authError.message);
        setStatus("input");
      }
      return;
    }

    // User is signed in — approve the device
    await approveDevice(code, session.access_token);
  };

  const approveDevice = async (userCode: string, accessToken: string) => {
    setStatus("approving");
    try {
      const resp = await fetch("/api/v1/auth/device/approve", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          user_code: userCode.replace(/-/g, ""),
        }),
      });

      if (resp.ok) {
        setStatus("done");
      } else {
        const data = await resp.json();
        setError(data.error || "Failed to approve device");
        setStatus("error");
      }
    } catch {
      setError("Failed to connect. Please try again.");
      setStatus("error");
    }
  };

  // Handle OAuth redirect — runs once on mount
  const redirectHandled = useRef(false);
  useEffect(() => {
    if (redirectHandled.current) return;
    const params = new URLSearchParams(window.location.search);
    const redirectCode = params.get("code");
    const storedCode = localStorage.getItem("phantom_device_code");

    if (redirectCode && storedCode) {
      redirectHandled.current = true;
      setCode(storedCode);
      localStorage.removeItem("phantom_device_code");

      getSupabase().auth.getSession().then(({ data: { session } }) => {
        if (session) {
          approveDevice(storedCode, session.access_token);
        }
      });
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="min-h-screen bg-[#050508] text-[#f5f5f7] flex items-center justify-center p-6">
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
                onChange={(e) => setCode(formatCode(e.target.value))}
                placeholder="XXXX-XXXX"
                className="w-full text-center text-3xl font-mono tracking-[0.3em] py-4 px-6 bg-[#0a0a12] border border-[#1a1a2c] rounded-lg text-[#f5f5f7] outline-none focus:border-blue-500 placeholder:text-[#333]"
                maxLength={9}
                autoFocus
                disabled={status !== "input"}
              />

              {error && (
                <p className="text-red-400 text-sm">{error}</p>
              )}

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
    </div>
  );
}
