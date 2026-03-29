export default function PricingPage() {
  return (
    <main className="min-h-screen flex flex-col items-center p-8 pt-24">
      <h1 className="text-4xl font-black tracking-tight mb-4">Pricing</h1>
      <p className="text-[#a1a1b5] mb-12">
        Start free. Upgrade when you need cloud sync.
      </p>

      <div className="grid md:grid-cols-3 gap-6 max-w-4xl w-full">
        {/* Free */}
        <div className="border border-[#1a1a2c] rounded-xl p-6">
          <h2 className="text-xl font-bold mb-2">Free</h2>
          <p className="text-3xl font-black mb-4">
            $0<span className="text-sm font-normal text-[#65657a]">/mo</span>
          </p>
          <ul className="space-y-2 text-sm text-[#a1a1b5] mb-6">
            <li>Local vault (keychain or encrypted file)</li>
            <li>Proxy with streaming support</li>
            <li>MCP server for Claude Code</li>
            <li>Unlimited local secrets</li>
            <li>1 cloud vault (up to 10 secrets)</li>
          </ul>
          <a
            href="https://github.com/ashlrai/phantom-secrets"
            className="block text-center py-2 border border-[#1a1a2c] rounded-lg hover:border-[#333] transition-colors"
          >
            Install Free
          </a>
        </div>

        {/* Pro */}
        <div className="border-2 border-blue-600 rounded-xl p-6 relative">
          <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-blue-600 text-xs font-bold px-3 py-1 rounded-full">
            POPULAR
          </span>
          <h2 className="text-xl font-bold mb-2">Pro</h2>
          <p className="text-3xl font-black mb-4">
            $8<span className="text-sm font-normal text-[#65657a]">/mo</span>
          </p>
          <ul className="space-y-2 text-sm text-[#a1a1b5] mb-6">
            <li>Everything in Free</li>
            <li>Unlimited cloud vaults</li>
            <li>Multi-device sync</li>
            <li>Priority support</li>
          </ul>
          <button className="w-full py-2 bg-blue-600 hover:bg-blue-700 rounded-lg font-semibold transition-colors">
            Subscribe
          </button>
        </div>

        {/* Enterprise */}
        <div className="border border-[#1a1a2c] rounded-xl p-6">
          <h2 className="text-xl font-bold mb-2">Enterprise</h2>
          <p className="text-3xl font-black mb-4">Custom</p>
          <ul className="space-y-2 text-sm text-[#a1a1b5] mb-6">
            <li>Everything in Pro</li>
            <li>Team vaults & sharing</li>
            <li>Audit log</li>
            <li>SSO/SAML</li>
            <li>Dedicated support</li>
          </ul>
          <a
            href="mailto:mason@ashlar.ai"
            className="block text-center py-2 border border-[#1a1a2c] rounded-lg hover:border-[#333] transition-colors"
          >
            Contact Us
          </a>
        </div>
      </div>
    </main>
  );
}
