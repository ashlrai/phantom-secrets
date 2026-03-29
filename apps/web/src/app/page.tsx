export default function Home() {
  return (
    <main className="min-h-screen flex flex-col items-center justify-center p-8">
      <h1 className="text-5xl font-black tracking-tight mb-4">
        Delegate everything to AI.
      </h1>
      <p className="text-[#a1a1b5] text-lg text-center max-w-xl mb-8">
        Let AI agents use your API keys without the security risk. Phantom
        replaces real secrets with worthless tokens and injects credentials at
        the network layer.
      </p>
      <div className="flex gap-4">
        <a
          href="https://github.com/ashlrai/phantom-secrets"
          className="px-6 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-semibold transition-colors"
        >
          Get Started
        </a>
        <a
          href="/pricing"
          className="px-6 py-3 border border-[#1a1a2c] hover:border-[#333] rounded-lg font-semibold transition-colors"
        >
          Pricing
        </a>
      </div>
    </main>
  );
}
