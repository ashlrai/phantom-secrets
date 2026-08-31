// Three-step quick-start panel. Each step has the exact command,
// click-to-copy, and an explicitly illustrative output summary. Ports,
// service routes, and vault backends vary by machine and configuration.

import { CopyButton } from "./CopyButton";

const STEPS = [
  {
    n: "01",
    title: "Install v0.7.3 on macOS",
    body: "Use the reviewed Homebrew tap, trust, and fully qualified formula path.",
    cmd: "brew tap ashlrai/phantom\nbrew trust --formula ashlrai/phantom/phantom\nbrew install ashlrai/phantom/phantom",
    out: `$ phantom --version
phantom 0.7.3
$ phantom-mcp --version
phantom-mcp 0.7.3`,
  },
  {
    n: "02",
    title: "Protect and verify",
    body: "Initialize the project, then run the built-in readiness preflight.",
    cmd: "phantom init && phantom agent doctor",
    out: `$ phantom init
ok  vault initialized · <selected backend>
ok  .env rewritten with phm_ tokens
$ phantom agent doctor
ok  status: verified
ok  vault accessible
ok  env files protected
ok  Phantom MCP wiring detected`,
  },
  {
    n: "03",
    title: "Code with AI normally",
    body: "Supported HTTP SDK routes use fresh session tokens through the authenticated local proxy.",
    cmd: "phantom exec -- claude",
    out: `$ phantom exec -- claude
->  Starting proxy with <n> secret(s)...
ok  Proxy running on 127.0.0.1:<ephemeral-port>
->  <configured SDK base URL overrides>
->  launching claude`,
  },
];

export function QuickStart() {
  return (
    <section id="quickstart" className="border-t border-border py-24 sm:py-28">
      <div className="mx-auto max-w-[1100px] px-7">
        <div className="max-w-[640px] mb-12">
          <h2 className="text-[1.8rem] sm:text-[2.4rem] font-extrabold tracking-[-0.035em] leading-[1.08] text-white">
            A bounded path to a protected .env.
          </h2>
          <p className="mt-4 text-[0.98rem] text-t2 leading-[1.65]">
            Three commands with illustrative output; ports, routes, and vault
            backends vary by configuration. Linux and Windows use the exact
            v0.7.3 GitHub release assets linked in the repository. For exact
            local state, run{" "}
            <code className="font-mono text-blue-b">phantom agent doctor</code>.
          </p>
        </div>

        <div className="space-y-3">
          {STEPS.map((s) => (
            <div
              key={s.n}
              className="grid grid-cols-1 lg:grid-cols-[1fr_1.15fr] gap-5 lg:gap-7 rounded-2xl border border-border bg-s1 p-6 sm:p-7"
            >
              <div>
                <div className="font-mono text-[0.78rem] text-blue-b mb-2">
                  Step {s.n}
                </div>
                <h3 className="text-[1.1rem] font-bold text-t1 mb-2">
                  {s.title}
                </h3>
                <p className="text-[0.9rem] text-t2 leading-[1.65] mb-4">
                  {s.body}
                </p>
                <CopyButton text={s.cmd} />
              </div>
              <pre className="rounded-lg border border-border bg-bg/70 p-4 font-mono text-[0.78rem] leading-[1.7] text-t1 overflow-x-auto whitespace-pre">
                {s.out}
              </pre>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
