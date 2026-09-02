import Link from "next/link";

export default function VercelSuccessPage() {
  return (
    <div className="min-h-screen bg-[#050508] text-[#f5f5f7] flex items-center justify-center p-6">
      <div className="max-w-md text-center">
        <div className="w-16 h-16 bg-green-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
          <svg className="w-8 h-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <h1 className="text-2xl font-bold mb-2">Vercel OAuth is unavailable</h1>
        <p className="text-[#a1a1b5] mb-6">
          The hosted OAuth integration is disabled while Phantom completes
          user-bound state validation and encrypted token storage. The CLI sync
          workflow remains separately configured and governed.
        </p>
        <Link href="/" className="text-blue-400 hover:text-blue-300">
          Back to Phantom
        </Link>
      </div>
    </div>
  );
}
