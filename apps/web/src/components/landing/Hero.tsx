import { EXACT_ROUTE_ENTRIES } from "./BrandLogos";
import { CarouselPauseButton } from "./CarouselPauseButton";
import { Github } from "./Icons";
import { SocialProof } from "./SocialProof";

export function Hero() {
  return (
    <header className="elite-hero overflow-hidden">
      <div className="elite-hero__halo" aria-hidden="true" />
      <div className="mx-auto max-w-[940px] px-7 pt-16 text-center sm:pt-24">
        <p className="mx-auto inline-flex items-center gap-2 rounded-full border border-border bg-s1/80 px-3 py-1 text-[0.72rem] font-medium text-t2 backdrop-blur-md">
          <span className="h-1.5 w-1.5 rounded-full bg-blue" aria-hidden="true" />
          API key security for Claude Code · Cursor · Windsurf · Codex
        </p>

        <h1 className="mt-7 text-[clamp(2.7rem,6.4vw,4.9rem)] font-extrabold leading-[0.98] tracking-[-0.05em] text-white">
          Let AI coding agents use APIs.
          {" "}
          <span className="mt-2 block bg-gradient-to-br from-blue-b via-blue to-blue-d bg-clip-text text-transparent">
            Keep provider keys out of their context.
          </span>
        </h1>

        <p className="mx-auto mt-6 max-w-[650px] text-[1rem] leading-[1.7] text-t2 sm:text-[1.06rem]">
          Phantom is an open-source, local-first credential boundary. It moves
          managed project secrets behind value-blind{" "}
          <code className="font-mono text-[0.92em] text-blue-b">phm_</code>{" "}
          placeholders, then injects route-owned credentials through an
          authenticated local proxy for explicitly supported HTTP routes.
        </p>

        <div className="mt-8 flex flex-wrap justify-center gap-2.5">
          <a
            href="#install"
            className="inline-flex min-h-11 items-center rounded-lg bg-blue px-5 py-2.5 text-[0.9rem] font-semibold text-white no-underline transition-colors hover:bg-blue-d"
          >
            Choose macOS, Windows, or Linux
          </a>
          <a
            href="https://github.com/ashlrai/phantom-secrets"
            aria-label="Star Phantom on GitHub"
            className="inline-flex min-h-11 items-center gap-2 rounded-lg border border-border-l bg-s1 px-5 py-2.5 text-[0.9rem] font-semibold text-t1 no-underline transition-colors hover:border-blue"
          >
            <Github className="h-4 w-4" aria-hidden="true" />
            Star Phantom on GitHub
          </a>
        </div>

        <SocialProof />
      </div>

      <CredentialWall />
    </header>
  );
}

function CredentialWall() {
  const firstRow = EXACT_ROUTE_ENTRIES.filter((_, index) => index % 2 === 0);
  const secondRow = EXACT_ROUTE_ENTRIES.filter((_, index) => index % 2 === 1);

  return (
    <section
      className="relative mt-16 border-b border-border pb-20 sm:mt-20 sm:pb-24"
      aria-label="Provider identities in Phantom's closed trusted-route registry"
    >
      <p className="mx-auto mb-7 max-w-[940px] px-7 text-center text-[0.72rem] font-medium tracking-[0.12em] text-t3">
        {EXACT_ROUTE_ENTRIES.length} provider identities in Phantom&apos;s closed trusted-route registry
      </p>
      <div className="mx-auto mb-4 flex max-w-[940px] justify-end px-7">
        <CarouselPauseButton controls="trusted-route-marquee" label="trusted-route carousel" />
      </div>
      <div id="trusted-route-marquee" className="elite-marquee space-y-3 sm:space-y-4">
        <CredentialRow items={firstRow} />
        <CredentialRow items={secondRow} reverse />
      </div>
      <p className="mx-auto mt-6 max-w-[760px] px-7 text-center text-[0.72rem] leading-6 text-t3">
        A registry entry defines an available exact HTTP route, not automatic setup,
        endorsement, or support for every provider operation. Some routes require
        explicit configuration; unsupported destinations and protocols fail closed.
        Phantom is not a sandbox, and upstream traffic still reaches the provider.
      </p>
    </section>
  );
}

function CredentialRow({
  items,
  reverse = false,
}: {
  items: typeof EXACT_ROUTE_ENTRIES;
  reverse?: boolean;
}) {
  return (
    <div className="overflow-hidden py-1">
      <div className={`elite-marquee__track${reverse ? " elite-marquee__track--reverse" : ""}`}>
        {[...items, ...items].map((item, index) => (
          <article
            className="group flex w-[300px] shrink-0 items-center gap-3 rounded-xl border border-border bg-s1 px-4 py-3"
            key={`${item.name}-${index}`}
            aria-hidden={index >= items.length ? "true" : undefined}
          >
            <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-border-l bg-s2">
              <item.Logo className="h-5 w-5" aria-hidden="true" />
            </span>
            <span className="min-w-0 flex-1 text-left">
              <strong className="block truncate text-[0.82rem] text-t1">{item.name}</strong>
              <code className="block truncate text-[0.65rem] text-t3">{item.env}=</code>
            </span>
            <code className="shrink-0 text-[0.65rem] text-blue-b">{item.token}</code>
          </article>
        ))}
      </div>
    </div>
  );
}
