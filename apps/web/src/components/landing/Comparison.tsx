// Scoped comparison of Phantom's managed workflow with direct plaintext
// dotenv access. This deliberately avoids unverified third-party claims.

import { Check } from "./Icons";

// Special tokens get icon rendering; any other string is rendered as-is.
type Cell = "yes" | "no" | "n/a" | string;

type PathKey = "phantom" | "rawEnv";

type Row = { label: string } & Record<PathKey, Cell>;

const ROWS: Row[] = [
  {
    label: "Value-blind managed agent path",
    phantom: "yes",
    rawEnv: "no",
  },
  {
    label: "Open source",
    phantom: "yes",
    rawEnv: "n/a",
  },
  {
    label: "Local-first vault",
    phantom: "yes",
    rawEnv: "n/a",
  },
  {
    label: "MCP-native (supported clients)",
    phantom: "yes",
    rawEnv: "no",
  },
  {
    label: "Staged dotenv and prefix checks",
    phantom: "yes",
    rawEnv: "no",
  },
  {
    label: "Fresh proxy authorization per exec session",
    phantom: "yes",
    rawEnv: "n/a",
  },
  {
    label: "Configured-upstream boundary for supported HTTP routes",
    phantom: "yes",
    rawEnv: "no",
  },
];

const PATHS: { key: PathKey; label: string; featured: boolean }[] = [
  { key: "phantom", label: "Phantom", featured: true },
  { key: "rawEnv", label: "Plaintext agent .env", featured: false },
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

export function Comparison() {
  return (
    <section id="comparison" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1200px] px-7">
        <div className="max-w-[640px] mb-12">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            Why not just use what you have?
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            Phantom addresses a narrow boundary: supported agent-driven HTTP
            requests can use configured credentials without placing provider
            values in the agent&apos;s dotenv context. This compares Phantom&apos;s
            managed path with giving an agent a plaintext dotenv value; it is
            not a vendor feature benchmark.
          </p>
        </div>

        <div
          aria-label="Credential boundary comparison"
          className="-mx-7 overflow-x-auto px-7 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-b"
          role="region"
          tabIndex={0}
        >
          <div className="min-w-[620px] rounded-2xl border border-border bg-s1 overflow-hidden">
            <table className="w-full table-fixed border-collapse">
              <caption className="sr-only">
                Boundary comparison: Phantom&apos;s managed path versus direct
                plaintext dotenv access.
              </caption>
              <colgroup>
                <col style={{ width: "48%" }} />
                {PATHS.map((c) => (
                  <col key={c.key} style={{ width: "26%" }} />
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
                  {PATHS.map((c) => (
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
                    {PATHS.map((c) => (
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
      </div>
    </section>
  );
}
