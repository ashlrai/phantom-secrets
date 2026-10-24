"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { initializePhantomWorld } from "./phantom-world";

export function PhantomWorld({ children }: { children: ReactNode }) {
  const container = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const root = container.current?.querySelector<HTMLElement>("#phantom-world");
    if (root) return initializePhantomWorld(root);
  }, []);
  return <div ref={container}>{children}</div>;
}
