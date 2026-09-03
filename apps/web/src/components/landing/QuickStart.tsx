import { CopyButton } from "./CopyButton";
import {
  PUBLIC_RELEASE_RECEIPT,
  PUBLIC_RELEASE_TAG,
} from "@/lib/public-release";

const STEPS = [
  {
    step: `Install ${PUBLIC_RELEASE_TAG} on macOS`,
    body: "Use the reviewed Homebrew tap, trust, and fully qualified formula path.",
    command:
      "brew tap ashlrai/phantom\nbrew trust --formula ashlrai/phantom/phantom\nbrew install ashlrai/phantom/phantom",
    receipt: PUBLIC_RELEASE_RECEIPT,
  },
  {
    step: "Protect and inspect",
    body: "Initialize one project, then inspect its local readiness before launching an agent.",
    command: "phantom init\nphantom agent doctor",
    receipt: "vault accessible\ndotenv managed\nMCP wiring inspected",
  },
  {
    step: "Launch the bounded session",
    body: "Run a supported client through the authenticated loopback proxy.",
    command: "phantom exec -- claude",
    receipt:
      "127.0.0.1:<ephemeral-port>\nconfigured SDK route overrides\nfresh child authorization",
  },
] as const;

export function QuickStart() {
  return (
    <section className="passage-section" aria-labelledby="passage-title">
      <div className="landing-frame">
        <div className="landing-section-heading">
          <p className="landing-kicker">First passage</p>
          <h2 id="passage-title">Protect one project, then prove the boundary.</h2>
          <p>
            The output below is illustrative output. Ports, routes, vault
            backends, and local findings vary by machine and configuration.
            Linux and Windows use the exact {PUBLIC_RELEASE_TAG} GitHub release assets linked
            in the repository.
          </p>
        </div>

        <ol className="passage-steps">
          {STEPS.map((item, index) => (
            <li key={item.step}>
              <div className="passage-steps__number" aria-hidden="true">
                {String(index + 1).padStart(2, "0")}
              </div>
              <div className="passage-steps__instruction">
                <h3>{item.step}</h3>
                <p>{item.body}</p>
                <CopyButton text={item.command} />
              </div>
              <div className="passage-steps__receipt">
                <span>illustrative receipt</span>
                <pre>{item.receipt}</pre>
              </div>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
