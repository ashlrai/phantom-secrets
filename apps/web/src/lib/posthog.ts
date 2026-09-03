type EventProperties = Record<string, string | number | boolean | null | undefined>;

let clientPromise: Promise<typeof import("posthog-js")["default"] | null> | null = null;

function canonicalBrowserUrl() {
  return `${window.location.origin}${window.location.pathname}`;
}

export function initPostHog() {
  if (typeof window === "undefined") return Promise.resolve(null);

  const key = process.env.NEXT_PUBLIC_POSTHOG_KEY;
  if (!key) return Promise.resolve(null);
  if (clientPromise) return clientPromise;

  clientPromise = import("posthog-js")
    .then(({ default: posthog }) => {
      if (!posthog.__loaded) {
        posthog.init(key, {
          api_host: process.env.NEXT_PUBLIC_POSTHOG_HOST || "https://us.i.posthog.com",
          person_profiles: "identified_only",
          // Pageviews are emitted by the provider with a query-free canonical URL.
          // OAuth and device codes must never reach analytics.
          capture_pageview: false,
          capture_pageleave: false,
          autocapture: false,
          capture_performance: false,
          disable_capture_url_hashes: true,
          disable_persistence: true,
          disable_session_recording: true,
          save_campaign_params: false,
          save_referrer: false,
          advanced_disable_flags: true,
          advanced_disable_toolbar_metrics: true,
          before_send: (event) => {
            if (!event) return null;
            event.properties = {
              ...event.properties,
              $current_url: canonicalBrowserUrl(),
              $pathname: window.location.pathname,
            };
            return event;
          },
        });
      }

      return posthog;
    })
    .catch(() => null);

  return clientPromise;
}

export async function capturePostHog(event: string, properties?: EventProperties) {
  const posthog = await initPostHog();
  if (!posthog?.__loaded || typeof window === "undefined") return;

  try {
    posthog.capture(event, {
      ...properties,
      $current_url: canonicalBrowserUrl(),
      $pathname: window.location.pathname,
    });
  } catch {
    // Analytics is optional and must never disrupt the user workflow.
  }
}
