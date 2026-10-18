# Next.js

A minimal Next.js 16 app (App Router) run under `phantom exec`. The server
reads `OPENAI_API_KEY` and `OPENAI_BASE_URL` from its environment. Under
Phantom the key is a `phm_` placeholder and the base URL points at a local
proxy on `127.0.0.1`; the real value never enters the app's environment or any
project file.

```sh
node examples/nextjs/run.mjs --phantom /absolute/path/phantom
```

The recipe works in a disposable HOME and workspace with a fake, non-provider
key and an encrypted-file vault. It runs `phantom init`, `npm install`,
`next build`, then `phantom exec -- npx next start`, and checks that
`/api/status` reports a placeholder key, a local proxy URL and a healthy proxy.
It exits `0` (passed), `1` (failed) or `2` (binary or network missing).

Use it in your own app:

```sh
phantom init
phantom exec -- npm run dev
```

Trust boundary: this proves the Next.js server process receives only
placeholders. It makes no call to a real provider. Server code that logs
`process.env` still prints only placeholders, but never send `OPENAI_BASE_URL`
(it can embed the proxy token) to the browser. It needs network access for
`npm install` and is not part of the CI recipe test.
