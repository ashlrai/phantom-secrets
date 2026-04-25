// Side-by-side .env transformation — the most concrete demonstration of
// what Phantom actually does. Real code, real diff.

// Values are deliberately truncated mid-string so they read as real keys
// without matching any provider's live-key format (and without tripping
// GitHub secret scanning on this very demo).
const BEFORE = [
  { k: "OPENAI_API_KEY", v: "sk-proj-aB3xK9…" },
  { k: "ANTHROPIC_API_KEY", v: "sk-ant-api03-9X2v…" },
  { k: "STRIPE_SECRET_KEY", v: "sk_live_51HxAb…" },
  { k: "DATABASE_URL", v: "postgres://app:••••@db.prod:5432/app" },
];

const AFTER = [
  { k: "OPENAI_API_KEY", v: "phm_a8f2c4d9e1b7" },
  { k: "ANTHROPIC_API_KEY", v: "phm_2ccb5a91f604" },
  { k: "STRIPE_SECRET_KEY", v: "phm_491e6dc8a273" },
  { k: "DATABASE_URL", v: "phm_99a8d2bf17e0" },
];

function EnvBlock({
  title,
  subtitle,
  rows,
  variant,
}: {
  title: string;
  subtitle: string;
  rows: { k: string; v: string }[];
  variant: "before" | "after";
}) {
  return (
    <div className="rounded-2xl border border-border bg-s1 overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-border bg-s2/60">
        <div className="flex items-center gap-2">
          <span
            className={
              "inline-block h-2 w-2 rounded-full " +
              (variant === "before" ? "bg-red" : "bg-green")
            }
          />
          <span className="font-mono text-[0.78rem] text-t2">.env</span>
        </div>
        <span className="text-[0.7rem] uppercase tracking-[0.12em] text-t3">
          {title}
        </span>
      </div>
      <pre className="px-5 py-5 font-mono text-[0.82rem] leading-[1.85] overflow-x-auto">
        {rows.map((r) => (
          <div key={r.k} className="whitespace-nowrap">
            <span className="text-t3">{r.k}</span>
            <span className="text-t3">=</span>
            <span
              className={variant === "before" ? "text-red/90" : "text-blue-b"}
            >
              {r.v}
            </span>
          </div>
        ))}
      </pre>
      <div className="px-5 py-3 border-t border-border text-[0.76rem] text-t3">
        {subtitle}
      </div>
    </div>
  );
}

export function Transformation() {
  return (
    <section className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1100px] px-7">
        <div className="max-w-[640px] mb-12">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            Same workflow. Different posture.
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            One command rewrites your <code className="font-mono text-blue-b">.env</code>.
            Real secrets move to the vault. AI sees only the phantoms.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <EnvBlock
            title="Before"
            subtitle="What AI sees if you paste your .env into Claude or Cursor."
            rows={BEFORE}
            variant="before"
          />
          <EnvBlock
            title="After phantom init"
            subtitle="What AI sees now. Decoys only. Proxy injects the real keys."
            rows={AFTER}
            variant="after"
          />
        </div>
      </div>
    </section>
  );
}
