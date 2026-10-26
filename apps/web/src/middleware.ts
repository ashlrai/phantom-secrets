import { NextResponse } from "next/server";

const RETIRED_INSTALLER_MESSAGE = [
  "Phantom's network installer endpoint is unavailable.",
  "Do not pipe network responses into a shell.",
  "Install the pinned public release by following https://phm.dev/docs/getting-started#exact-github-assets-macos-linux-and-windows",
  "",
].join("\n");

export function middleware() {
  return new NextResponse(RETIRED_INSTALLER_MESSAGE, {
    status: 410,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

export const config = {
  matcher: ["/install.sh", "/install.ps1"],
};
