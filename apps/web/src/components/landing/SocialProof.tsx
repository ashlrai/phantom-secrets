import { Check, Github } from "./Icons";
import { PUBLIC_RELEASE_TAG } from "@/lib/public-release";

const BADGES = [
  { label: "MIT licensed", href: "https://github.com/ashlrai/phantom-secrets/blob/main/LICENSE" },
  { label: "Rust source", href: "https://github.com/ashlrai/phantom-secrets" },
  { label: `Release ${PUBLIC_RELEASE_TAG}`, href: `https://github.com/ashlrai/phantom-secrets/releases/tag/${PUBLIC_RELEASE_TAG}` },
  { label: "Six native targets", href: `https://github.com/ashlrai/phantom-secrets/releases/tag/${PUBLIC_RELEASE_TAG}` },
  { label: "SHA-256 manifest", href: `https://github.com/ashlrai/phantom-secrets/releases/download/${PUBLIC_RELEASE_TAG}/SHA256SUMS` },
  { label: "SPDX SBOMs", href: `https://github.com/ashlrai/phantom-secrets/releases/tag/${PUBLIC_RELEASE_TAG}` },
  { label: "Threat model", href: "https://github.com/ashlrai/phantom-secrets/blob/main/SECURITY.md" },
] as const;

export function SocialProof() {
  return (
    <div className="mt-7 flex flex-col items-center gap-4">
      <div className="flex flex-wrap justify-center gap-2">
        {BADGES.map(({ label, href }) => (
          <a
            key={label}
            href={href}
            className="inline-flex items-center gap-1.5 rounded-full border border-border bg-s1/60 px-2.5 py-1 text-[0.72rem] font-medium text-t2 no-underline transition-colors hover:border-blue hover:text-t1"
          >
            <Check className="h-2.5 w-2.5 shrink-0 text-green" strokeWidth={3} aria-hidden="true" />
            {label}
          </a>
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
