"use client";

import { useEffect, useState, type DependencyList } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { getBrowserClient } from "./supabase-browser";

/**
 * Run a Supabase query and expose `{ data, error, loading }`. The four
 * dashboard pages all needed this exact useState + useEffect dance —
 * this hook is the canonical version.
 *
 * Usage:
 *
 *   const { data, error, loading } = useSupabaseQuery<UserRow>(
 *     (sb) => sb.from("users").select("plan, github_login").single(),
 *   );
 *
 * The `build` callback is given a fresh client from `getBrowserClient`
 * and must return a Supabase query (which is itself a thenable resolving
 * to `{ data, error }`). Pass `deps` if the query depends on a prop or
 * route param — the hook re-runs when they change.
 *
 * Cancellation: if the component unmounts (or deps change) before the
 * query resolves, the result is dropped — no setState on an unmounted
 * component.
 */
export function useSupabaseQuery<T>(
  // Build returns any Supabase query (which is itself a PromiseLike of
  // { data, error }). We cast `data` to T inside the hook because
  // Supabase's inferred row types use array-shaped joins that don't
  // line up with the simpler shapes callers usually want — letting the
  // caller specify T directly is cleaner than fighting the inference.
  build: (sb: SupabaseClient) => PromiseLike<{
    data: unknown;
    error: { message: string } | null;
  }>,
  deps: DependencyList = [],
): { data: T | null; error: string | null; loading: boolean } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.resolve(build(getBrowserClient())).then((res) => {
      if (cancelled) return;
      if (res.error) {
        setError(res.error.message);
      } else {
        setData(res.data as T | null);
      }
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
    // build is recreated on every render — it's the deps array that
    // controls re-run, not the function identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading };
}
