"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";
import { capturePostHog } from "@/lib/posthog";

export function PostHogProvider({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  useEffect(() => {
    void capturePostHog("$pageview", {
      $current_url: `${window.location.origin}${pathname}`,
    });
  }, [pathname]);

  return <>{children}</>;
}
