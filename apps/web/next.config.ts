import type { NextConfig } from "next";
import docsRoutes from "./docs-routes.json";
import { publicAuthConfigurationFingerprint } from "./src/lib/public-auth-configuration";

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "script-src 'self' 'unsafe-inline' https://*.i.posthog.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self' https://*.supabase.co wss://*.supabase.co https://*.i.posthog.com",
  "worker-src 'self' blob:",
  "upgrade-insecure-requests",
].join("; ");

const SECURITY_HEADERS = [
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-site" },
  { key: "X-Permitted-Cross-Domain-Policies", value: "none" },
  { key: "Content-Security-Policy", value: CONTENT_SECURITY_POLICY },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=()",
  },
];

const NOINDEX_HEADERS = [
  { key: "X-Robots-Tag", value: "noindex, nofollow" },
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  env: {
    // This non-secret digest is frozen into server code at build time. Runtime
    // injection cannot turn a missing or different browser configuration into
    // a ready one.
    PHANTOM_PUBLIC_AUTH_CONFIGURATION_FINGERPRINT:
      publicAuthConfigurationFingerprint(process.env) ?? "unconfigured",
  },
  async redirects() {
    const legacyDocs = docsRoutes.map(({ source, file }) => ({
      source,
      destination: `https://github.com/ashlrai/phantom-secrets/blob/main/docs/${file}`,
      permanent: false,
    }));

    return legacyDocs;
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: SECURITY_HEADERS,
      },
      {
        source: "/dashboard/:path*",
        headers: NOINDEX_HEADERS,
      },
      {
        source: "/device/:path*",
        headers: NOINDEX_HEADERS,
      },
      {
        source: "/integrations/:path*",
        headers: NOINDEX_HEADERS,
      },
    ];
  },
};

export default nextConfig;
