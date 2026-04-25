import { CopyButton } from "./CopyButton";
import { GitHubLogo } from "./BrandLogos";

export function CTA() {
  return (
    <section className="border-t border-border py-28 sm:py-36">
      <div className="mx-auto max-w-[720px] px-7 text-center">
        <h2 className="font-extrabold tracking-[-0.04em] leading-[1.04] text-white text-[clamp(2rem,4.6vw,3.2rem)]">
          Stop rationing.
          <br />
          <span className="text-t3">Start delegating.</span>
        </h2>

        <div className="mt-8 mx-auto max-w-[440px]">
          <CopyButton text="npx phantom-secrets init" />
        </div>

        <div className="mt-5 flex justify-center gap-4 text-[0.84rem]">
          <a
            href="https://github.com/ashlrai/phantom-secrets"
            className="inline-flex items-center gap-1.5 text-t2 hover:text-t1 transition-colors"
          >
            <GitHubLogo className="h-3.5 w-3.5" />
            ashlrai/phantom-secrets
          </a>
          <span className="text-t3">·</span>
          <span className="text-t3">MIT licensed</span>
          <span className="text-t3">·</span>
          <span className="text-t3">Local-first</span>
        </div>
      </div>
    </section>
  );
}
