"use client";

import dynamic from "next/dynamic";
import { useEffect, useState } from "react";
import { TheSwap } from "./TheSwap";

const Hero3DScene = dynamic(
  () => import("./Hero3DScene").then((m) => m.Hero3DScene),
  { ssr: false, loading: () => <FallbackPlaceholder /> },
);

function FallbackPlaceholder() {
  return (
    <div
      className="relative mx-auto aspect-[4/3] w-full max-w-[760px]"
      aria-hidden
    >
      <div
        className="pointer-events-none absolute inset-0 -z-10 blur-3xl opacity-70"
        style={{
          background:
            "radial-gradient(ellipse at 50% 45%, rgba(59,130,246,0.32) 0%, transparent 65%)",
        }}
      />
    </div>
  );
}

function useShouldUse3D() {
  // null = undecided (still SSR / first paint). Render fallback until we know.
  const [enable, setEnable] = useState<boolean | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const small = window.matchMedia("(max-width: 768px)").matches;
    const lowDpr = (window.devicePixelRatio || 1) < 1;

    // Detect WebGL2 capability — fail open if check itself fails
    let webgl2 = true;
    try {
      const canvas = document.createElement("canvas");
      webgl2 = !!canvas.getContext("webgl2");
    } catch {
      webgl2 = false;
    }

    // Save-Data hint
    type Conn = { saveData?: boolean };
    const conn = (navigator as Navigator & { connection?: Conn }).connection;
    const saveData = !!conn?.saveData;

    setEnable(!reduce && !small && webgl2 && !saveData && !lowDpr);
  }, []);

  return enable;
}

export function Hero3D() {
  const enable = useShouldUse3D();

  if (enable === null) return <FallbackPlaceholder />;
  if (!enable) return <TheSwap />;
  return <Hero3DScene />;
}
