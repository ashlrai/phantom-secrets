export function SiteFooter() {
  return (
    <footer className="border-t border-border py-8 text-center text-[0.8rem] text-t3">
      <p>
        Built by{" "}
        <a
          href="https://ashlr.ai"
          className="text-t2 hover:text-blue-b transition-colors"
        >
          AshlrAI
        </a>{" "}
        ·{" "}
        <a
          href="https://github.com/ashlrai/phantom-secrets"
          className="text-t2 hover:text-blue-b transition-colors"
        >
          GitHub
        </a>{" "}
        ·{" "}
        <a
          href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md"
          className="text-t2 hover:text-blue-b transition-colors"
        >
          Docs
        </a>{" "}
        ·{" "}
        <a
          href="/pricing"
          className="text-t2 hover:text-blue-b transition-colors"
        >
          Pricing
        </a>{" "}
        · MIT License
      </p>
    </footer>
  );
}
