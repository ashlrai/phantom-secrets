import Link from "next/link";
import { SECRET_USE_CASES, secretUseCasePath } from "@/lib/secret-use-cases";

export function SecretUseCases() {
  return (
    <section id="use-cases" className="docs-gateway" aria-labelledby="secret-use-cases-title">
      <div className="landing-frame">
        <div className="landing-section-heading">
          <p className="landing-kicker">Choose your next task</p>
          <h2 id="secret-use-cases-title">Put the credential boundary to work.</h2>
        </div>
        <div className="docs-gateway__grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 16rem), 1fr))" }}>
          {SECRET_USE_CASES.map((guide) => (
            <article key={guide.slug}>
              <h3><Link href={secretUseCasePath(guide.slug)}>{guide.title}</Link></h3>
              <p>Follow the steps, check the limits, and inspect the source for each claim.</p>
              <Link href={secretUseCasePath(guide.slug)}>Read the workflow</Link>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
