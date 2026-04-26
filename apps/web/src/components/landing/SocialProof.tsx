// Trust signals — small chip row that lives right below the hero CTAs.
// Free conversion lift: a security tool with no visible trust badges
// fails its own value prop.

import { Check, Github } from "./Icons";

const BADGES = [
  "MIT licensed",
  "Open source",
  "Local-first",
  "End-to-end encrypted",
  "Zero data sent",
];

export function SocialProof() {
  return (
    <div className="mt-7 flex flex-col items-center gap-4">
      <div className="flex flex-wrap justify-center gap-2">
        {BADGES.map((label) => (
          <span
            key={label}
            className="inline-flex items-center gap-1.5 rounded-full border border-border bg-s1/60 px-2.5 py-1 text-[0.72rem] font-medium text-t2 backdrop-blur-md"
          >
            <Check
              className="h-2.5 w-2.5 text-green/80 shrink-0"
              strokeWidth={3}
              aria-hidden
            />
            {label}
          </span>
        ))}
      </div>
      <a
        href="https://github.com/ashlrai/phantom-secrets"
        className="inline-flex items-center gap-1.5 text-[0.78rem] font-medium text-t3 hover:text-t1 transition-colors no-underline"
      >
        <Github className="h-3.5 w-3.5" />
        github.com/ashlrai/phantom-secrets →
      </a>
    </div>
  );
}
