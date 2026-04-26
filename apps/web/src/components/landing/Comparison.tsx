// Comparison matrix — Phantom vs alternatives. Critical for security
// buyers who need to justify the choice over what they already have.

import { Check } from "./Icons";

// Special tokens get icon rendering; any other string is rendered as-is.
type Cell = "yes" | "no" | "n/a" | "limited" | string;

type CompetitorKey =
  | "phantom"
  | "rawEnv"
  | "doppler"
  | "onePassword"
  | "infisical"
  | "awsSm";

type Row = { label: string } & Record<CompetitorKey, Cell>;

const ROWS: Row[] = [
  {
    label: "AI tools never see real keys",
    phantom: "yes",
    rawEnv: "no",
    doppler: "no",
    onePassword: "no",
    infisical: "no",
    awsSm: "no",
  },
  {
    label: "Open source",
    phantom: "yes",
    rawEnv: "n/a",
    doppler: "no",
    onePassword: "no",
    infisical: "yes",
    awsSm: "no",
  },
  {
    label: "Local-first vault",
    phantom: "yes",
    rawEnv: "yes",
    doppler: "no",
    onePassword: "yes",
    infisical: "no",
    awsSm: "no",
  },
  {
    label: "MCP-native (every editor)",
    phantom: "yes",
    rawEnv: "no",
    doppler: "no",
    onePassword: "no",
    infisical: "no",
    awsSm: "no",
  },
  {
    label: "Pre-commit secret scanning",
    phantom: "yes",
    rawEnv: "no",
    doppler: "yes",
    onePassword: "no",
    infisical: "yes",
    awsSm: "no",
  },
  {
    label: "Free tier",
    phantom: "yes",
    rawEnv: "n/a",
    doppler: "limited",
    onePassword: "no",
    infisical: "yes",
    awsSm: "limited",
  },
  {
    label: "Setup time",
    phantom: "10 seconds",
    rawEnv: "—",
    doppler: "minutes",
    onePassword: "minutes",
    infisical: "minutes",
    awsSm: "hours",
  },
  {
    label: "Cloud sync (E2E encrypted)",
    phantom: "yes",
    rawEnv: "no",
    doppler: "yes",
    onePassword: "yes",
    infisical: "yes",
    awsSm: "yes",
  },
];

const COMPETITORS: { key: CompetitorKey; label: string; featured: boolean }[] = [
  { key: "phantom", label: "Phantom", featured: true },
  { key: "rawEnv", label: ".env file", featured: false },
  { key: "doppler", label: "Doppler", featured: false },
  { key: "onePassword", label: "1Password CLI", featured: false },
  { key: "infisical", label: "Infisical", featured: false },
  { key: "awsSm", label: "AWS Secrets Mgr", featured: false },
];

const CELL_BASE = "inline-flex items-center gap-1.5 text-[0.84rem]";
const ICON_SIZE = "h-3.5 w-3.5";

function CellRender({ value, isPhantom }: { value: Cell; isPhantom: boolean }) {
  switch (value) {
    case "yes":
      return (
        <span className={`${CELL_BASE} ${isPhantom ? "text-green font-medium" : "text-t2"}`}>
          <Check
            className={`${ICON_SIZE} ${isPhantom ? "text-green" : "text-t3"}`}
            strokeWidth={3}
          />
          Yes
        </span>
      );
    case "no":
      return (
        <span className={`${CELL_BASE} text-t3`}>
          <Cross className={`${ICON_SIZE} text-t3/60`} />
          No
        </span>
      );
    case "n/a":
      return <span className="text-[0.84rem] text-t3">—</span>;
    case "limited":
      return (
        <span className={`${CELL_BASE} text-t3`}>
          <Dash className={`${ICON_SIZE} text-t3/60`} />
          Limited
        </span>
      );
    default:
      return (
        <span className={`text-[0.84rem] ${isPhantom ? "text-green font-medium" : "text-t2"}`}>
          {value}
        </span>
      );
  }
}

function Cross({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.4"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <path d="M18 6 6 18M6 6l12 12" />
    </svg>
  );
}

function Dash({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.4"
      strokeLinecap="round"
      className={className}
      aria-hidden
    >
      <path d="M5 12h14" />
    </svg>
  );
}

export function Comparison() {
  return (
    <section id="comparison" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1200px] px-7">
        <div className="max-w-[640px] mb-12">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            Why not just use what you have?
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            Every other secrets manager assumes the wrong threat model.
            They protect secrets <em className="not-italic text-t1">at rest</em>{" "}
            and <em className="not-italic text-t1">in transit</em> — but the
            moment you give one to an AI tool, it leaks. Phantom protects
            them <em className="not-italic text-t1">in context</em>.
          </p>
        </div>

        <div className="overflow-x-auto -mx-7 px-7">
          <div className="min-w-[820px] rounded-2xl border border-border bg-s1 overflow-hidden">
            <table className="w-full table-fixed border-collapse">
              <caption className="sr-only">
                Capability comparison: Phantom vs five alternative secrets
                managers.
              </caption>
              <colgroup>
                <col style={{ width: "22%" }} />
                {COMPETITORS.map((c) => (
                  <col key={c.key} style={{ width: "13%" }} />
                ))}
              </colgroup>
              <thead className="bg-s2/40">
                <tr className="border-b border-border">
                  <th
                    scope="col"
                    className="px-5 py-4 text-left text-[0.75rem] font-mono uppercase tracking-[0.1em] text-t3"
                  >
                    Capability
                  </th>
                  {COMPETITORS.map((c) => (
                    <th
                      key={c.key}
                      scope="col"
                      className={
                        "px-3 py-4 text-[0.82rem] font-bold text-center " +
                        (c.featured ? "text-blue-b" : "text-t2")
                      }
                    >
                      {c.label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ROWS.map((row) => (
                  <tr
                    key={row.label}
                    className="border-b border-border last:border-b-0"
                  >
                    <th
                      scope="row"
                      className="px-5 py-4 text-left text-[0.88rem] text-t1 font-medium"
                    >
                      {row.label}
                    </th>
                    {COMPETITORS.map((c) => (
                      <td
                        key={c.key}
                        className={
                          "px-3 py-4 text-center align-middle " +
                          (c.featured ? "bg-blue/[0.04]" : "")
                        }
                      >
                        <CellRender
                          value={row[c.key]}
                          isPhantom={c.featured}
                        />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <p className="mt-6 text-[0.78rem] text-t3 max-w-[820px]">
          Comparison reflects each tool&apos;s default tier and primary
          use-case as of April 2026. Phantom is purpose-built for the
          AI-coding-tool workflow; the others are general-purpose secrets
          managers retrofitted to the same problem.
        </p>
      </div>
    </section>
  );
}
