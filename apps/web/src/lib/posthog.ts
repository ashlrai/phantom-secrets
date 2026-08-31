import posthog from "posthog-js";

export function initPostHog() {
  if (typeof window === "undefined") return;
  if (posthog.__loaded) return;

  const key = process.env.NEXT_PUBLIC_POSTHOG_KEY;
  if (!key) return;

  posthog.init(key, {
    api_host: process.env.NEXT_PUBLIC_POSTHOG_HOST || "https://us.i.posthog.com",
    person_profiles: "identified_only",
    // Pageviews are emitted by the provider with a query-free canonical URL.
    // OAuth and device codes must never reach analytics.
    capture_pageview: false,
    capture_pageleave: false,
    autocapture: false,
  });
}

export { posthog };
