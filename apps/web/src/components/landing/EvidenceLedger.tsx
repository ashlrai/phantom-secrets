import { COMMERCIAL_CONTACT } from "@/lib/commercial-offerings";

const EVIDENCE = [
  {
    artifact: "Security boundary",
    proof: "Threat model, security policy, and documented residual risks",
    href: "https://github.com/ashlrai/phantom-secrets/blob/main/THREAT_MODEL.md",
    link: "Review the threat model",
  },
  {
    artifact: "Release supply chain",
    proof: "Exact archives, checksums, SPDX SBOMs, and provenance verification contracts",
    href: "https://github.com/ashlrai/phantom-secrets/blob/main/docs/release-readiness.md",
    link: "Review release evidence",
  },
  {
    artifact: "Native platform matrix",
    proof: "Explicit macOS, Linux, and Windows build and acceptance boundaries",
    href: "https://github.com/ashlrai/phantom-secrets/blob/main/docs/platform-support.md",
    link: "Review platform support",
  },
  {
    artifact: "Adoption decision",
    proof: "A bounded pilot, named owners, acceptance criteria, and separate activation gates",
    href: "https://github.com/ashlrai/phantom-secrets/blob/main/docs/enterprise-adoption.md",
    link: "Plan an evaluation",
  },
] as const;

export function EvidenceLedger() {
  return (
    <section className="evidence-section" aria-labelledby="evidence-title">
      <div className="landing-frame">
        <div className="landing-section-heading evidence-section__heading">
          <p className="landing-kicker">Evidence before assurance</p>
          <h2 id="evidence-title">Inspect the proof. Keep the claims bounded.</h2>
          <p>
            Source, tests, a release receipt, a deployed service, and an accepted
            organizational control prove different things. Phantom&apos;s public
            documentation keeps those gates separate.
          </p>
        </div>

        <div className="evidence-ledger">
          <div className="evidence-ledger__head" aria-hidden="true">
            <span>Artifact</span>
            <span>What it can establish</span>
            <span>Inspect</span>
          </div>
          {EVIDENCE.map((item) => (
            <article key={item.artifact}>
              <h3>{item.artifact}</h3>
              <p>{item.proof}</p>
              <a href={item.href}>{item.link}</a>
            </article>
          ))}
        </div>

        <div className="commercial-brief">
          <div>
            <p className="landing-kicker">Enterprise and public sector</p>
            <h3>Adopt the open core. Scope the rest in writing.</h3>
          </div>
          <p>
            Organizations can evaluate the MIT-licensed local product without a
            contract. Hosted, team, deployment, procurement, support, and
            public-sector requirements are available for bounded evaluation by
            written agreement with Ashlr AI. No certification or authorization
            is represented. SSO/SAML is not shipped, and no contractual SLA is
            represented as active.
          </p>
          <a
            className="sealed-button sealed-button--primary"
            href={`mailto:${COMMERCIAL_CONTACT}?subject=Phantom%20enterprise%20or%20public-sector%20evaluation`}
          >
            Scope an evaluation
          </a>
        </div>
      </div>
    </section>
  );
}
