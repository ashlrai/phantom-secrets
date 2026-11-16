type EventProperties = Record<string, string | number | boolean | null | undefined>;

let clientPromise: Promise<typeof import("posthog-js")["default"] | null> | null = null;

// Pageviews are for PostHog project 688217. NEXT_PUBLIC_POSTHOG_KEY selects
// that project. The public key is never hardcoded. An unset key or Do Not
// Track skips capture.

function canonicalBrowserUrl() {
  return `${window.location.origin}${window.location.pathname}`;
}

export function trackingAllowed(key: string | undefined, doNotTrackValue: string | null | undefined) {
  if (!key) return false;
  return doNotTrackValue !== "1" && doNotTrackValue !== "yes";
}

function doNotTrackEnabled() {
  if (typeof navigator === "undefined") return false;
  const navigatorWithLegacy = navigator as Navigator & { msDoNotTrack?: string };
  const windowWithLegacy = window as Window & { doNotTrack?: string };
  return [navigator.doNotTrack, navigatorWithLegacy.msDoNotTrack, windowWithLegacy.doNotTrack]
    .some((value) => !trackingAllowed("present", value));
}

function pageProperties() {
  return {
    $current_url: canonicalBrowserUrl(),
    $pathname: window.location.pathname,
    $host: window.location.host,
  };
}

function initPostHog() {
  if (typeof window === "undefined") return Promise.resolve(null);

  const key = process.env.NEXT_PUBLIC_POSTHOG_KEY;
  if (!key || !trackingAllowed(key, null) || doNotTrackEnabled()) return Promise.resolve(null);
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
            if (!event || doNotTrackEnabled()) return null;
            event.properties = {
              ...event.properties,
              ...pageProperties(),
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
  if (typeof window === "undefined" || doNotTrackEnabled()) return;
  const posthog = await initPostHog();
  if (!posthog?.__loaded) return;

  try {
    posthog.capture(event, {
      ...properties,
      ...pageProperties(),
    });
  } catch {
    // Analytics is optional and must never disrupt the user workflow.
  }
}
