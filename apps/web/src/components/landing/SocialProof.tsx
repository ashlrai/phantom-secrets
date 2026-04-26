// Trust signals — small chip row that lives right below the hero CTAs.
// Free conversion lift: a security tool with no visible trust badges
// fails its own value prop.

import { GitHubLogo } from "./BrandLogos";

const BADGES = [
  { label: "MIT licensed" },
  { label: "Open source" },
  { label: "Local-first" },
  { label: "End-to-end encrypted" },
  { label: "Zero data sent" },
];

export function SocialProof() {
  return (
    <div className="mt-7 flex flex-col items-center gap-4">
      <div className="flex flex-wrap justify-center gap-2">
        {BADGES.map((b) => (
          <span
            key={b.label}
            className="inline-flex items-center gap-1.5 rounded-full border border-border bg-s1/60 px-2.5 py-1 text-[0.72rem] font-medium text-t2 backdrop-blur-md"
          >
            <CheckDot />
            {b.label}
          </span>
        ))}
      </div>
      <a
        href="https://github.com/ashlrai/phantom-secrets"
        className="inline-flex items-center gap-1.5 text-[0.78rem] font-medium text-t3 hover:text-t1 transition-colors no-underline"
      >
        <GitHubLogo className="h-3.5 w-3.5" />
        github.com/ashlrai/phantom-secrets →
      </a>
    </div>
  );
}

function CheckDot() {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="text-green/80 shrink-0"
      aria-hidden
    >
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}
