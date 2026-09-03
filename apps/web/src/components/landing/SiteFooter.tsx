import Image from "next/image";
import Link from "next/link";

const linkClass =
  "text-[0.84rem] text-t3 no-underline transition-colors hover:text-t1";

export function SiteFooter() {
  return (
    <footer className="border-t border-border bg-s1/30">
      <div className="mx-auto grid max-w-[1200px] gap-10 px-7 py-12 sm:grid-cols-2 lg:grid-cols-[1.5fr_repeat(3,1fr)] lg:py-16">
        <div className="max-w-sm">
          <Link
            href="/"
            aria-label="Phantom home"
            className="inline-flex items-center gap-2.5 text-t1 no-underline"
          >
            <Image src="/favicon.svg" alt="" width={22} height={22} />
            <span className="font-bold tracking-tight">Phantom</span>
          </Link>
          <p className="mt-4 text-[0.86rem] leading-6 text-t3">
            Open-source, local-first infrastructure for governed credential
            handling in agentic engineering workflows.
          </p>
          <p className="mt-4 text-[0.78rem] leading-5 text-t3">
            Built by{" "}
            <a href="https://ashlr.ai" className="text-t2 hover:text-blue-b">
              Ashlr AI
            </a>
            . Enterprise and government evaluations are scoped by
            written agreement.
          </p>
        </div>

        <nav aria-label="Product links">
          <h2 className="text-[0.74rem] font-semibold uppercase tracking-[0.14em] text-t2">
            Product
          </h2>
          <ul className="mt-4 space-y-3">
            <li>
              <Link href="/#features" className={linkClass}>
                Features
              </Link>
            </li>
            <li>
              <Link href="/pricing" className={linkClass}>
                Pricing
              </Link>
            </li>
            <li>
              <Link href="/security" className={linkClass}>
                Security
              </Link>
            </li>
            <li>
              <a
                href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md"
                className={linkClass}
              >
                Documentation
              </a>
            </li>
          </ul>
        </nav>

        <nav aria-label="Organization links">
          <h2 className="text-[0.74rem] font-semibold uppercase tracking-[0.14em] text-t2">
            Organizations
          </h2>
          <ul className="mt-4 space-y-3">
            <li>
              <Link href="/enterprise" className={linkClass}>
                Enterprise
              </Link>
            </li>
            <li>
              <Link href="/government" className={linkClass}>
                Government
              </Link>
            </li>
            <li>
              <a
                href="mailto:mason@ashlr.ai?subject=Phantom%20organization%20evaluation"
                className={linkClass}
              >
                Contact Ashlr AI
              </a>
            </li>
          </ul>
        </nav>

        <nav aria-label="Open-source project links">
          <h2 className="text-[0.74rem] font-semibold uppercase tracking-[0.14em] text-t2">
            Open source
          </h2>
          <ul className="mt-4 space-y-3">
            <li>
              <a
                href="https://github.com/ashlrai/phantom-secrets"
                className={linkClass}
              >
                GitHub repository
              </a>
            </li>
            <li>
              <a
                href="https://github.com/ashlrai/phantom-secrets/blob/main/CONTRIBUTING.md"
                className={linkClass}
              >
                Contributing
              </a>
            </li>
            <li>
              <a
                href="https://github.com/ashlrai/phantom-secrets/blob/main/ROADMAP.md"
                className={linkClass}
              >
                Roadmap
              </a>
            </li>
            <li>
              <a
                href="https://github.com/ashlrai/phantom-secrets/blob/main/LICENSE"
                className={linkClass}
              >
                MIT license
              </a>
            </li>
          </ul>
        </nav>
      </div>

      <div className="border-t border-border/70">
        <div className="mx-auto flex max-w-[1200px] flex-col gap-2 px-7 py-5 text-[0.75rem] text-t3 sm:flex-row sm:items-center sm:justify-between">
          <p>© 2026 Ashlr AI. Phantom is open-source software.</p>
          <p>Hosted services and support require separate commissioning.</p>
        </div>
      </div>
    </footer>
  );
}
