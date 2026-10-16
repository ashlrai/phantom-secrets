export const dynamic = "force-dynamic";
// Server component: it only ever sees the placeholder, never the real key.
export default function Page() {
  const key = process.env.OPENAI_API_KEY ?? "";
  return <main><h1>Phantom + Next.js</h1><p>Key prefix seen by the server: {key.slice(0, 4)}</p></main>;
}
