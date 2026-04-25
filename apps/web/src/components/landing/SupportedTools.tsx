import { Reveal } from "./Reveal";

type Category = "AI Coding" | "AI API" | "Infra" | "Database";

interface Service {
  name: string;
  category: Category;
}

const SERVICES: Service[] = [
  // AI Coding tools
  { name: "Claude Code", category: "AI Coding" },
  { name: "Cursor", category: "AI Coding" },
  { name: "Windsurf", category: "AI Coding" },
  { name: "Codex", category: "AI Coding" },
  { name: "Continue", category: "AI Coding" },
  { name: "Cline", category: "AI Coding" },
  // AI APIs
  { name: "OpenAI", category: "AI API" },
  { name: "Anthropic", category: "AI API" },
  { name: "Google AI", category: "AI API" },
  { name: "Mistral", category: "AI API" },
  // Infra
  { name: "Vercel", category: "Infra" },
  { name: "Railway", category: "Infra" },
  { name: "Stripe", category: "Infra" },
  { name: "Supabase", category: "Infra" },
  { name: "GitHub", category: "Infra" },
  // Databases
  { name: "PostgreSQL", category: "Database" },
  { name: "MongoDB", category: "Database" },
];

const CATEGORY_COLORS: Record<Category, string> = {
  "AI Coding": "text-blue-b",
  "AI API":    "text-blue",
  Infra:       "text-t3",
  Database:    "text-t3",
};

function ServiceCard({ service }: { service: Service }) {
  return (
    <div className="group flex items-center gap-2.5 rounded-xl border border-border bg-s1 px-4 py-3 transition-all duration-150 hover:border-border-l hover:-translate-y-0.5 hover:bg-s2 hover-lift">
      {/* Green status dot */}
      <span
        aria-hidden
        className="shrink-0 w-1.5 h-1.5 rounded-full bg-green"
        style={{ boxShadow: "0 0 6px 1px rgba(34,197,94,0.55)" }}
      />
      <span className="text-[0.82rem] font-medium text-t1 leading-none">
        {service.name}
      </span>
      <span
        className={`ml-auto text-[0.68rem] font-medium tracking-[0.06em] uppercase ${CATEGORY_COLORS[service.category]} opacity-60`}
      >
        {service.category}
      </span>
    </div>
  );
}

export function SupportedTools() {
  return (
    <section
      id="integrations"
      className="border-t border-border py-20 sm:py-24"
    >
      <div className="mx-auto max-w-[1080px] px-7">
        <Reveal>
          <div className="text-center mb-12">
            <p className="text-[0.75rem] font-semibold tracking-[0.12em] uppercase text-blue mb-3">
              Integrations
            </p>
            <h2 className="text-[1.7rem] sm:text-[2.2rem] font-extrabold tracking-[-0.04em] text-white mb-3">
              Auto-detects 13+ services.
            </h2>
            <p className="mx-auto max-w-[460px] text-t2 text-[0.95rem] sm:text-base leading-[1.7]">
              If it has an API key, Phantom protects it. Detection is automatic
              — no config needed.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.05}>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
            {SERVICES.map((service) => (
              <ServiceCard key={service.name} service={service} />
            ))}
          </div>
        </Reveal>

        {/* Subtle legend row */}
        <Reveal delay={0.1}>
          <div className="flex flex-wrap items-center justify-center gap-5 mt-10">
            {(Object.entries(CATEGORY_COLORS) as [Category, string][]).map(
              ([cat, cls]) => (
                <div key={cat} className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-green" />
                  <span className={`text-[0.72rem] font-medium uppercase tracking-[0.08em] ${cls} opacity-60`}>
                    {cat}
                  </span>
                </div>
              )
            )}
            <span className="text-[0.72rem] text-t3 opacity-50">
              · all verified
            </span>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
