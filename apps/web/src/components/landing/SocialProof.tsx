import { Check, Github } from "./Icons";

const BADGES = [
  "MIT licensed",
  "Local-first",
  "Six release targets",
  "Value-blind MCP tools",
  "Exact-route injection",
] as const;

export function SocialProof() {
  return (
    <div className="mt-7 flex flex-col items-center gap-4">
      <div className="flex flex-wrap justify-center gap-2">
        {BADGES.map((label) => (
          <span
            key={label}
            className="inline-flex items-center gap-1.5 rounded-full border border-border bg-s1/60 px-2.5 py-1 text-[0.72rem] font-medium text-t2"
          >
            <Check className="h-2.5 w-2.5 shrink-0 text-green" strokeWidth={3} aria-hidden="true" />
            {label}
          </span>
        ))}
      </div>
      <a
        href="https://github.com/ashlrai/phantom-secrets"
        className="inline-flex items-center gap-1.5 text-[0.78rem] font-medium text-t3 no-underline transition-colors hover:text-t1"
      >
        <Github className="h-3.5 w-3.5" aria-hidden="true" />
        Open the repository and star Phantom
      </a>
    </div>
  );
}
