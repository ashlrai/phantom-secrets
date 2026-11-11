import assert from "node:assert/strict";
import test from "node:test";

import { observeProduction } from "./observe.mjs";

test("sitemap routes and structured data types use code-unit order", async () => {
  const origin = "https://example.test";
  const paths = ["/z", "/a", "/Z", "/A"];
  const types = ["zebra", "apple", "Zebra", "Apple", "Apple"];
  const fetchImpl = async (url) => {
    if (url.pathname === "/sitemap.xml") {
      return new Response(paths.map((route) => `<loc>${origin}${route}</loc>`).join(""));
    }
    if (url.pathname === "/robots.txt") return new Response("");
    if (paths.includes(url.pathname)) {
      return new Response(
        `<script type="application/ld+json">${JSON.stringify({ "@type": types })}</script>`,
        { headers: { "content-type": "text/html" } },
      );
    }
    return new Response("{}", { status: 404 });
  };
  const report = await observeProduction({
    siteOrigin: origin,
    githubRepositoryApi: `${origin}/github`,
    networkPolicy: (url) => url.origin === origin,
    fetchImpl,
  });

  assert.deepEqual(report.technical.public_routes.map(({ route }) => route), ["/A", "/Z", "/a", "/z"]);
  for (const route of report.technical.public_routes) {
    assert.deepEqual(route.structured_data_types, ["Apple", "Zebra", "apple", "zebra"]);
  }
});
