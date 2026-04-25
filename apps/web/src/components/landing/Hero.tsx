"use client";

import type { ComponentType, SVGProps } from "react";
import { posthog } from "@/lib/posthog";
import { CopyButton } from "./CopyButton";
import {
  ClaudeLogo,
  CursorLogo,
  DockerLogo,
  GitHubLogo,
  MongoLogo,
  OpenAILogo,
  PostgresLogo,
  RailwayLogo,
  StripeLogo,
  SupabaseLogo,
  VercelLogo,
  WindsurfLogo,
} from "./BrandLogos";
import { Github } from "./Icons";

type LogoComponent = ComponentType<SVGProps<SVGSVGElement>>;

interface ApiKey {
  Logo: LogoComponent;
  name: string;
  env: string;
  token: string;
}

// Twelve real services, each with a real-shape env var name and a fixed
// phm_xxx token. Tokens are deterministic per service so the marquee
// always reads the same card-for-card on repeat passes.
const KEYS: ApiKey[] = [
  { Logo: OpenAILogo,   name: "OpenAI",     env: "OPENAI_API_KEY",     token: "phm_a8f2c4d9" },
  { Logo: ClaudeLogo,   name: "Anthropic",  env: "ANTHROPIC_API_KEY",  token: "phm_e1b773c0" },
  { Logo: StripeLogo,   name: "Stripe",     env: "STRIPE_SECRET_KEY",  token: "phm_2ccb5a91" },
  { Logo: VercelLogo,   name: "Vercel",     env: "VERCEL_TOKEN",       token: "phm_d9f1c102" },
  { Logo: GitHubLogo,   name: "GitHub",     env: "GITHUB_TOKEN",       token: "phm_99a8d2bf" },
  { Logo: SupabaseLogo, name: "Supabase",   env: "SUPABASE_KEY",       token: "phm_4f1c8ae3" },
  { Logo: CursorLogo,   name: "Cursor",     env: "CURSOR_API_KEY",     token: "phm_77b3e5f1" },
  { Logo: WindsurfLogo, name: "Windsurf",   env: "WINDSURF_API_KEY",   token: "phm_1c9e2a40" },
  { Logo: RailwayLogo,  name: "Railway",    env: "RAILWAY_TOKEN",      token: "phm_8b4d6f93" },
  { Logo: PostgresLogo, name: "Postgres",   env: "DATABASE_URL",       token: "phm_3a2e7c81" },
  { Logo: MongoLogo,    name: "MongoDB",    env: "MONGODB_URI",        token: "phm_6e0fb529" },
  { Logo: DockerLogo,   name: "Docker",     env: "DOCKER_TOKEN",       token: "phm_b5817d4c" },
];

export function Hero() {
  return (
    <header className="relative pt-14 pb-16 sm:pt-20 sm:pb-24 overflow-hidden">
      {/* Soft halo behind the headline */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-[680px] -z-10 opacity-60"
        style={{
          background:
            "radial-gradient(ellipse 60% 60% at 50% 0%, rgba(59,130,246,0.18) 0%, transparent 70%)",
        }}
      />

      <div className="mx-auto max-w-[940px] px-7 text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-border bg-s1/80 px-3 py-1 text-[0.72rem] font-medium text-t2 backdrop-blur-md">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue/60 opacity-75" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-blue" />
          </span>
          For Claude Code · Cursor · Windsurf · Codex
        </span>

        <h1 className="mt-7 font-extrabold tracking-[-0.045em] leading-[1.0] text-white text-[clamp(2.6rem,6.4vw,4.6rem)]">
          Delegate everything to AI.
          <br />
          <span className="bg-gradient-to-br from-blue-b via-blue to-blue-d bg-clip-text text-transparent">
            Without sharing a single key.
          </span>
        </h1>

        <p className="mt-6 mx-auto max-w-[600px] text-[0.98rem] sm:text-[1.04rem] leading-[1.65] text-t2">
          Phantom hands every AI tool a worthless{" "}
          <code className="font-mono text-blue-b text-[0.92em]">phm_</code>{" "}
          token. The local proxy injects the real key at the network layer.
          Full access. Zero exposure.
        </p>

        <div className="mt-8 mx-auto w-full max-w-[460px]">
          <CopyButton text="npx phantom-secrets init" />
        </div>

        <div className="mt-5 flex flex-wrap justify-center gap-2.5">
          <a
            href="#install"
            onClick={() => posthog.capture("hero_get_started_clicked")}
            className="inline-flex items-center gap-2 rounded-lg bg-blue px-5 py-2.5 text-[0.9rem] font-semibold text-white no-underline transition-all duration-200 hover:bg-blue-d hover:-translate-y-px hover:shadow-[0_4px_24px_rgba(59,130,246,0.32)]"
          >
            Get started
          </a>
          <a
            href="https://github.com/ashlrai/phantom-secrets"
            className="inline-flex items-center gap-2 rounded-lg border border-border-l bg-s1 px-5 py-2.5 text-[0.9rem] font-semibold text-t1 no-underline transition-colors duration-200 hover:border-t3"
          >
            <Github className="h-3.5 w-3.5" />
            View on GitHub
          </a>
        </div>
      </div>

      {/* Marquee of API key cards — full bleed past content max-width */}
      <KeyWall />
    </header>
  );
}

function KeyWall() {
  // Duplicate the array so the marquee loop is seamless when translated -50%
  const track = [...KEYS, ...KEYS];

  return (
    <section
      aria-label="Phantom protects API keys for every popular service"
      className="relative mt-16 sm:mt-20"
    >
      {/* Section label */}
      <p className="mx-auto max-w-[940px] px-7 text-center text-[0.78rem] font-medium uppercase tracking-[0.18em] text-t3 mb-7">
        Replaces real keys for every service you use
      </p>

      {/* Marquee — escapes any container, full viewport width */}
      <div className="relative">
        {/* Edge fade — left + right, mask out the marquee endpoints */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-y-0 left-0 z-10 w-32 sm:w-48 bg-gradient-to-r from-bg to-transparent"
        />
        <div
          aria-hidden
          className="pointer-events-none absolute inset-y-0 right-0 z-10 w-32 sm:w-48 bg-gradient-to-l from-bg to-transparent"
        />

        <div className="overflow-hidden marquee-pause-on-hover">
          <div className="flex gap-3 sm:gap-4 animate-[marquee_56s_linear_infinite] w-max marquee-track">
            {track.map((k, i) => (
              <KeyCard key={`${k.name}-${i}`} item={k} />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function KeyCard({ item }: { item: ApiKey }) {
  const { Logo, name, env, token } = item;
  return (
    <article
      className="group flex w-[260px] sm:w-[300px] shrink-0 items-center gap-4 rounded-xl border border-border bg-s1 px-4 py-3.5 transition-colors duration-200 hover:border-blue-d/60"
    >
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-border bg-s2 text-t2 transition-colors group-hover:text-t1">
        <Logo className="h-5 w-5" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-[0.84rem] font-semibold text-t1 truncate">
            {name}
          </span>
          <span className="text-[0.66rem] font-mono uppercase tracking-[0.06em] text-green/90">
            ● safe
          </span>
        </div>
        <div className="mt-1 font-mono text-[0.72rem] leading-tight truncate">
          <span className="text-t3">{env}=</span>
          <span className="text-blue-b">{token}</span>
        </div>
      </div>
    </article>
  );
}
