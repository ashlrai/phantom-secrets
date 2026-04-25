// Brand logos sourced from react-icons (SimpleIcons paths) for shape
// accuracy. Each component is a thin wrapper that applies the actual
// brand color, with overrides where the official hex is too dark to
// read on the navy background.
//
// For brands not in any major icon library (Cursor, Pinecone, Neon
// database), we fall back to hand-drawn approximations.

import type { SVGProps } from "react";
import {
  SiAnthropic,
  SiClaude,
  SiCloudflare,
  SiClerk,
  SiDatadog,
  SiDiscord,
  SiDocker,
  SiFigma,
  SiGithub,
  SiGooglecloud,
  SiGooglegemini,
  SiLinear,
  SiMistralai,
  SiMongodb,
  SiNotion,
  SiOpenai,
  SiPerplexity,
  SiPostgresql,
  SiPosthog,
  SiRailway,
  SiReplicate,
  SiResend,
  SiSendgrid,
  SiSentry,
  SiSlack,
  SiStripe,
  SiSupabase,
  SiTwilio,
  SiUpstash,
  SiVercel,
  SiWindsurf,
  SiX,
} from "react-icons/si";
import { TbBrandAws } from "react-icons/tb";
import type { IconBaseProps } from "react-icons";

type LogoProps = SVGProps<SVGSVGElement>;

// react-icons accept className + color via IconBaseProps; cast the
// SVG props through that interface so callers can pass className.
function asIconProps(props: LogoProps, color: string): IconBaseProps {
  return {
    color,
    className: props.className as string | undefined,
    style: props.style,
    "aria-label": props["aria-label"],
  };
}

/* ── AI APIs ─────────────────────────────────────────────────── */

export function OpenAILogo(props: LogoProps) {
  return <SiOpenai {...asIconProps(props, "#ffffff")} />;
}

export function ClaudeLogo(props: LogoProps) {
  return <SiClaude {...asIconProps(props, "#d97757")} />;
}

export function AnthropicLogo(props: LogoProps) {
  return <SiAnthropic {...asIconProps(props, "#d97757")} />;
}

export function XaiLogo(props: LogoProps) {
  return <SiX {...asIconProps(props, "#ffffff")} />;
}

export function GeminiLogo(props: LogoProps) {
  // Wrap the official Gemini path in our own SVG so we can apply the
  // canonical 3-stop diagonal gradient (which is Gemini's actual brand
  // identity — the icon is intrinsically multi-color).
  return (
    <svg viewBox="0 0 24 24" aria-label="Gemini" {...props}>
      <defs>
        <linearGradient id="gemini-grad" x1="15%" y1="15%" x2="85%" y2="85%">
          <stop offset="0%" stopColor="#4796E3" />
          <stop offset="50%" stopColor="#8E72E1" />
          <stop offset="100%" stopColor="#D96570" />
        </linearGradient>
      </defs>
      <path
        d="M12 24A14.304 14.304 0 0 0 0 12 14.304 14.304 0 0 0 12 0a14.304 14.304 0 0 0 12 12 14.304 14.304 0 0 0-12 12Z"
        fill="url(#gemini-grad)"
      />
    </svg>
  );
}

export function MistralLogo(props: LogoProps) {
  return <SiMistralai {...asIconProps(props, "#fa520f")} />;
}

export function PerplexityLogo(props: LogoProps) {
  return <SiPerplexity {...asIconProps(props, "#20b8cd")} />;
}

export function ReplicateLogo(props: LogoProps) {
  return <SiReplicate {...asIconProps(props, "#ffffff")} />;
}

/* ── Editors ─────────────────────────────────────────────────── */

export function CursorLogo(props: LogoProps) {
  // Not in SimpleIcons. Hand-drawn — the three-faced angular block
  // that matches Cursor's actual brand mark.
  return (
    <svg viewBox="0 0 24 24" aria-label="Cursor" {...props}>
      <path
        d="M11.925 24l10.425-6-10.425-6L1.5 18l10.425 6z"
        fill="#ffffff"
        opacity=".95"
      />
      <path
        d="M22.35 18V6L11.925 0v12l10.425 6z"
        fill="#ffffff"
        opacity=".7"
      />
      <path
        d="M11.925 0L1.5 6v12l10.425-6V0z"
        fill="#ffffff"
        opacity=".45"
      />
    </svg>
  );
}

export function WindsurfLogo(props: LogoProps) {
  return <SiWindsurf {...asIconProps(props, "#19b3a6")} />;
}

/* ── Infra ───────────────────────────────────────────────────── */

export function VercelLogo(props: LogoProps) {
  return <SiVercel {...asIconProps(props, "#ffffff")} />;
}

export function RailwayLogo(props: LogoProps) {
  return <SiRailway {...asIconProps(props, "#c6c6f5")} />;
}

export function AwsLogo(props: LogoProps) {
  // SimpleIcons removed AWS at Amazon's brand-policy request.
  // Tabler's TbBrandAws is the cleanest substitute.
  return <TbBrandAws {...asIconProps(props, "#ff9900")} />;
}

export function GcpLogo(props: LogoProps) {
  return <SiGooglecloud {...asIconProps(props, "#4285f4")} />;
}

export function CloudflareLogo(props: LogoProps) {
  return <SiCloudflare {...asIconProps(props, "#f48120")} />;
}

/* ── Databases ───────────────────────────────────────────────── */

export function SupabaseLogo(props: LogoProps) {
  return <SiSupabase {...asIconProps(props, "#3ecf8e")} />;
}

export function PostgresLogo(props: LogoProps) {
  return <SiPostgresql {...asIconProps(props, "#6f9ed4")} />;
}

export function MongoLogo(props: LogoProps) {
  return <SiMongodb {...asIconProps(props, "#47a248")} />;
}

export function NeonLogo(props: LogoProps) {
  // Neon (the serverless Postgres) isn't in SimpleIcons. Their brand
  // mark is a stylized "N" with a downward-arrow tail.
  return (
    <svg viewBox="0 0 24 24" aria-label="Neon" fill="#00e699" {...props}>
      <path d="M3 3h3.6l8.4 11.5V3h3v15.5L20 22h-3.4l-8.6-12V21H5v-3.5L3 14.5z" />
    </svg>
  );
}

export function UpstashLogo(props: LogoProps) {
  return <SiUpstash {...asIconProps(props, "#00e9a3")} />;
}

export function PineconeLogo(props: LogoProps) {
  // Pinecone (vector DB) isn't in SimpleIcons. Hand-drawn cone shape.
  return (
    <svg viewBox="0 0 24 24" aria-label="Pinecone" fill="#ffffff" {...props}>
      <path d="M11 2h2v3h-2z" />
      <path d="M12 5l-3 4h6l-3-4z" />
      <path d="M12 9l-5 4h10l-5-4z" />
      <path d="M12 13l-7 4h14l-7-4z" />
      <path d="M12 17l-3 5h6l-3-5z" />
    </svg>
  );
}

/* ── Comms ───────────────────────────────────────────────────── */

export function StripeLogo(props: LogoProps) {
  return <SiStripe {...asIconProps(props, "#635bff")} />;
}

export function TwilioLogo(props: LogoProps) {
  return <SiTwilio {...asIconProps(props, "#f22f46")} />;
}

export function ResendLogo(props: LogoProps) {
  return <SiResend {...asIconProps(props, "#ffffff")} />;
}

export function SendGridLogo(props: LogoProps) {
  return <SiSendgrid {...asIconProps(props, "#1a82e2")} />;
}

export function SlackLogo(props: LogoProps) {
  // Brand color #4A154B is their dark aubergine. On dark bg use the
  // brighter pink quadrant for legibility.
  return <SiSlack {...asIconProps(props, "#e01e5a")} />;
}

export function DiscordLogo(props: LogoProps) {
  return <SiDiscord {...asIconProps(props, "#5865f2")} />;
}

/* ── Auth ────────────────────────────────────────────────────── */

export function ClerkLogo(props: LogoProps) {
  return <SiClerk {...asIconProps(props, "#6c47ff")} />;
}

/* ── Observability ───────────────────────────────────────────── */

export function PostHogLogo(props: LogoProps) {
  return <SiPosthog {...asIconProps(props, "#f9bd2b")} />;
}

export function SentryLogo(props: LogoProps) {
  // Brand #362D59 is too dark on dark bg — use Sentry's light-mode
  // accent #b399ff which they ship for dark contexts.
  return <SiSentry {...asIconProps(props, "#b399ff")} />;
}

export function DatadogLogo(props: LogoProps) {
  // Brand #632CA6 too dark — lift to a brighter Datadog purple.
  return <SiDatadog {...asIconProps(props, "#9d6bd1")} />;
}

/* ── Dev ─────────────────────────────────────────────────────── */

export function GitHubLogo(props: LogoProps) {
  return <SiGithub {...asIconProps(props, "#ffffff")} />;
}

export function DockerLogo(props: LogoProps) {
  return <SiDocker {...asIconProps(props, "#2496ed")} />;
}

export function NotionLogo(props: LogoProps) {
  return <SiNotion {...asIconProps(props, "#ffffff")} />;
}

export function LinearLogo(props: LogoProps) {
  return <SiLinear {...asIconProps(props, "#5e6ad2")} />;
}

export function FigmaLogo(props: LogoProps) {
  return <SiFigma {...asIconProps(props, "#f24e1e")} />;
}

/* ── Data ────────────────────────────────────────────────────── */

interface LogoEntry {
  Logo: (p: LogoProps) => React.JSX.Element;
  name: string;
  color: string;
  category: "ai" | "editor" | "infra" | "db" | "comms" | "dev" | "auth" | "obs";
  env: string;
  token: string;
}

export const KEY_ENTRIES: LogoEntry[] = [
  // AI APIs
  { Logo: OpenAILogo,     name: "OpenAI",      color: "#ffffff", category: "ai",     env: "OPENAI_API_KEY",      token: "phm_a8f2c4d9" },
  { Logo: ClaudeLogo,     name: "Anthropic",   color: "#d97757", category: "ai",     env: "ANTHROPIC_API_KEY",   token: "phm_e1b773c0" },
  { Logo: XaiLogo,        name: "xAI",         color: "#ffffff", category: "ai",     env: "XAI_API_KEY",         token: "phm_4a91c70b" },
  { Logo: GeminiLogo,     name: "Gemini",      color: "#8e72e1", category: "ai",     env: "GEMINI_API_KEY",      token: "phm_38d2e6a4" },
  { Logo: MistralLogo,    name: "Mistral",     color: "#fa520f", category: "ai",     env: "MISTRAL_API_KEY",     token: "phm_b6c1f827" },
  { Logo: PerplexityLogo, name: "Perplexity",  color: "#20b8cd", category: "ai",     env: "PERPLEXITY_API_KEY",  token: "phm_05fa9d3e" },
  { Logo: ReplicateLogo,  name: "Replicate",   color: "#ffffff", category: "ai",     env: "REPLICATE_API_TOKEN", token: "phm_e8c40b71" },

  // Editors
  { Logo: CursorLogo,     name: "Cursor",      color: "#ffffff", category: "editor", env: "CURSOR_API_KEY",      token: "phm_77b3e5f1" },
  { Logo: WindsurfLogo,   name: "Windsurf",    color: "#19b3a6", category: "editor", env: "WINDSURF_API_KEY",    token: "phm_1c9e2a40" },

  // Infra
  { Logo: VercelLogo,     name: "Vercel",      color: "#ffffff", category: "infra",  env: "VERCEL_TOKEN",        token: "phm_d9f1c102" },
  { Logo: RailwayLogo,    name: "Railway",     color: "#c6c6f5", category: "infra",  env: "RAILWAY_TOKEN",       token: "phm_8b4d6f93" },
  { Logo: AwsLogo,        name: "AWS",         color: "#ff9900", category: "infra",  env: "AWS_SECRET_KEY",      token: "phm_5e2a8d61" },
  { Logo: GcpLogo,        name: "GCP",         color: "#4285f4", category: "infra",  env: "GCP_API_KEY",         token: "phm_c7f9b203" },
  { Logo: CloudflareLogo, name: "Cloudflare",  color: "#f48120", category: "infra",  env: "CF_API_TOKEN",        token: "phm_ae15f627" },

  // Databases
  { Logo: SupabaseLogo,   name: "Supabase",    color: "#3ecf8e", category: "db",     env: "SUPABASE_KEY",        token: "phm_4f1c8ae3" },
  { Logo: PostgresLogo,   name: "Postgres",    color: "#6f9ed4", category: "db",     env: "DATABASE_URL",        token: "phm_3a2e7c81" },
  { Logo: MongoLogo,      name: "MongoDB",     color: "#47a248", category: "db",     env: "MONGODB_URI",         token: "phm_6e0fb529" },
  { Logo: NeonLogo,       name: "Neon",        color: "#00e699", category: "db",     env: "NEON_API_KEY",        token: "phm_aa9d34f0" },
  { Logo: UpstashLogo,    name: "Upstash",     color: "#00e9a3", category: "db",     env: "UPSTASH_REDIS_TOKEN", token: "phm_3fc0e851" },
  { Logo: PineconeLogo,   name: "Pinecone",    color: "#ffffff", category: "db",     env: "PINECONE_API_KEY",    token: "phm_b71204e5" },

  // Comms
  { Logo: StripeLogo,     name: "Stripe",      color: "#635bff", category: "comms",  env: "STRIPE_SECRET_KEY",   token: "phm_2ccb5a91" },
  { Logo: TwilioLogo,     name: "Twilio",      color: "#f22f46", category: "comms",  env: "TWILIO_AUTH_TOKEN",   token: "phm_9d4b3e12" },
  { Logo: ResendLogo,     name: "Resend",      color: "#ffffff", category: "comms",  env: "RESEND_API_KEY",      token: "phm_f1a82b57" },
  { Logo: SendGridLogo,   name: "SendGrid",    color: "#1a82e2", category: "comms",  env: "SENDGRID_API_KEY",    token: "phm_2940bf16" },
  { Logo: SlackLogo,      name: "Slack",       color: "#e01e5a", category: "comms",  env: "SLACK_BOT_TOKEN",     token: "phm_71e0d493" },
  { Logo: DiscordLogo,    name: "Discord",     color: "#5865f2", category: "comms",  env: "DISCORD_BOT_TOKEN",   token: "phm_e74cb201" },

  // Auth
  { Logo: ClerkLogo,      name: "Clerk",       color: "#6c47ff", category: "auth",   env: "CLERK_SECRET_KEY",    token: "phm_8af216c3" },

  // Observability
  { Logo: PostHogLogo,    name: "PostHog",     color: "#f9bd2b", category: "obs",    env: "POSTHOG_API_KEY",     token: "phm_d2bf1e95" },
  { Logo: SentryLogo,     name: "Sentry",      color: "#b399ff", category: "obs",    env: "SENTRY_AUTH_TOKEN",   token: "phm_3187a4d0" },
  { Logo: DatadogLogo,    name: "Datadog",     color: "#9d6bd1", category: "obs",    env: "DATADOG_API_KEY",     token: "phm_f5e290bc" },

  // Dev
  { Logo: GitHubLogo,     name: "GitHub",      color: "#ffffff", category: "dev",    env: "GITHUB_TOKEN",        token: "phm_99a8d2bf" },
  { Logo: DockerLogo,     name: "Docker",      color: "#2496ed", category: "dev",    env: "DOCKER_TOKEN",        token: "phm_b5817d4c" },
  { Logo: NotionLogo,     name: "Notion",      color: "#ffffff", category: "dev",    env: "NOTION_API_KEY",      token: "phm_d04c1f86" },
  { Logo: LinearLogo,     name: "Linear",      color: "#5e6ad2", category: "dev",    env: "LINEAR_API_KEY",      token: "phm_e2f37a91" },
  { Logo: FigmaLogo,      name: "Figma",       color: "#f24e1e", category: "dev",    env: "FIGMA_TOKEN",         token: "phm_82bd5a14" },
];

export const LOGOS = KEY_ENTRIES.map(({ Logo, name }) => ({ Logo, name }));
