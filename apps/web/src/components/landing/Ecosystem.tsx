import { EXACT_ROUTE_ENTRIES, KEY_ENTRIES } from "./BrandLogos";
import { CarouselPauseButton } from "./CarouselPauseButton";

const exactRouteNames = new Set(EXACT_ROUTE_ENTRIES.map((item) => item.name));
const agentAndDeployNames = new Set(["Cursor", "Windsurf", "Vercel", "Railway"]);
const agentAndDeployEntries = KEY_ENTRIES.filter((item) => agentAndDeployNames.has(item.name));
const vaultExamples = KEY_ENTRIES.filter(
  (item) => !exactRouteNames.has(item.name) && !agentAndDeployNames.has(item.name),
);

const ROWS = [
  { label: "Selected editor and deployment credentials", items: agentAndDeployEntries },
  { label: "Additional vault-detection examples", items: vaultExamples },
] as const;

function LogoRow({
  label,
  items,
  reverse = false,
}: {
  label: string;
  items: typeof KEY_ENTRIES;
  reverse?: boolean;
}) {
  return (
    <div className="ecosystem-row" aria-label={label}>
      <span className="ecosystem-row__label">{label}</span>
      <div
        className={`ecosystem-track${reverse ? " ecosystem-track--reverse" : ""}`}
      >
        {[...items, ...items].map((item, index) => (
          <article
            className="ecosystem-card"
            key={`${item.name}-${index}`}
            aria-hidden={index >= items.length ? "true" : undefined}
          >
            <span className="ecosystem-card__logo" style={{ "--brand": item.color } as React.CSSProperties}>
              <item.Logo aria-hidden="true" />
            </span>
            <span className="ecosystem-card__copy">
              <strong>{item.name}</strong>
              <code>{item.env}</code>
            </span>
            <code className="ecosystem-card__token">{item.token}</code>
          </article>
        ))}
      </div>
    </div>
  );
}

export function Ecosystem() {
  return (
    <section className="ecosystem-section" aria-labelledby="ecosystem-title">
      <div className="landing-frame ecosystem-section__heading">
        <p className="landing-kicker">Your stack, without the plaintext</p>
        <h2 id="ecosystem-title">Every logo has a defined place in the boundary.</h2>
        <p>
          Phantom can move detected project secrets into a local vault and leave
          managed placeholders behind. The trusted-route identities are above;
          these rows cover selected editor/deployment credentials and additional
          vaulting examples, so visual breadth never becomes a support claim.
        </p>
      </div>

      <div className="landing-frame ecosystem-section__controls">
        <CarouselPauseButton controls="credential-ecosystem-marquee" label="credential ecosystem carousel" />
      </div>

      <div id="credential-ecosystem-marquee" className="ecosystem-marquee" aria-label="Examples of developer services whose credentials can be vaulted">
        {ROWS.map((row, index) => (
          <LogoRow
            key={row.label}
            label={row.label}
            items={row.items}
            reverse={index % 2 === 1}
          />
        ))}
      </div>

      <p className="landing-frame ecosystem-section__note">
        Logos identify products, not endorsement. Exact-route registry entries
        can still require explicit configuration. Detection depends on the key
        name or value shape; vaulting, client setup, deployment sync, and runtime
        injection remain separate capabilities.
      </p>
    </section>
  );
}
