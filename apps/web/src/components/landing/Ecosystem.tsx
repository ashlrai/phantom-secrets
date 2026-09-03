import { KEY_ENTRIES } from "./BrandLogos";
import { CarouselPauseButton } from "./CarouselPauseButton";

const firstRow = KEY_ENTRIES.filter((_, index) => index % 2 === 0);
const secondRow = KEY_ENTRIES.filter((_, index) => index % 2 === 1);

function LogoRow({
  items,
  reverse = false,
}: {
  items: typeof KEY_ENTRIES;
  reverse?: boolean;
}) {
  return (
    <div className="ecosystem-row">
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
        <h2 id="ecosystem-title">One local boundary across the tools agents touch.</h2>
        <p>
          Phantom can move detected project secrets into a local vault and leave
          managed placeholders behind. The examples below show common developer
          services; provider logos identify their products and do not imply
          endorsement or universal proxy support.
        </p>
      </div>

      <div className="landing-frame ecosystem-section__controls">
        <CarouselPauseButton controls="ecosystem-marquee" />
      </div>

      <div
        id="ecosystem-marquee"
        className="ecosystem-marquee"
        aria-label="Examples of developer services whose credentials can be vaulted"
      >
        <LogoRow items={firstRow} />
        <LogoRow items={secondRow} reverse />
      </div>

      <p className="landing-frame ecosystem-section__note">
        Vaulting and HTTP injection are separate. Runtime injection is limited
        to Phantom&apos;s explicitly configured, exact-match proxy routes; unsupported
        protocols fail closed.
      </p>
    </section>
  );
}
