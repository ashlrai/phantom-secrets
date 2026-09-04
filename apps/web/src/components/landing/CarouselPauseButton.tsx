"use client";

import { useState } from "react";

export function CarouselPauseButton({
  controls,
  label = "logo carousel",
}: {
  controls: string;
  label?: string;
}) {
  const [paused, setPaused] = useState(false);

  function toggleMotion() {
    const carousel = document.getElementById(controls);
    if (!carousel) return;

    const nextPaused = !paused;
    carousel.classList.toggle("logo-marquee--paused", nextPaused);
    setPaused(nextPaused);
  }

  return (
    <button
      type="button"
      className="logo-marquee__motion-toggle"
      aria-controls={controls}
      aria-pressed={paused}
      onClick={toggleMotion}
    >
      <svg viewBox="0 0 12 12" width="12" height="12" aria-hidden="true">
        {paused ? (
          <path d="M3 1.75 10 6l-7 4.25V1.75Z" fill="currentColor" />
        ) : (
          <path d="M2.25 1.5h2.5v9h-2.5v-9Zm5 0h2.5v9h-2.5v-9Z" fill="currentColor" />
        )}
      </svg>
      {paused ? `Resume ${label}` : `Pause ${label}`}
    </button>
  );
}
