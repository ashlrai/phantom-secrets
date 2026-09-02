import type { NextConfig } from "next";
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
    return [
      {
        source: "/docs",
        destination:
          "https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md",
        permanent: false,
      },
      {
        source: "/docs/getting-started",
        destination:
          "https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md",
        permanent: false,
      },
      {
        source: "/docs/login",
        destination:
          "https://github.com/ashlrai/phantom-secrets/blob/main/docs/login.md",
        permanent: false,
      },
      {
        source: "/docs/sync",
        destination:
          "https://github.com/ashlrai/phantom-secrets/blob/main/docs/sync.md",
        permanent: false,
      },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: SECURITY_HEADERS,
      },
    ];
  },
};

export default nextConfig;
