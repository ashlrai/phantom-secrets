"use client";

import { useState } from "react";

export function CarouselPauseButton({ controls }: { controls: string }) {
  const [paused, setPaused] = useState(false);

  function toggleMotion() {
    const carousel = document.getElementById(controls);
    if (!carousel) return;

    const nextPaused = !paused;
    carousel.classList.toggle("ecosystem-marquee--paused", nextPaused);
    setPaused(nextPaused);
  }

  return (
    <button
      type="button"
      className="ecosystem-section__motion-toggle"
      aria-controls={controls}
      aria-pressed={paused}
      onClick={toggleMotion}
    >
      <span aria-hidden="true">{paused ? "▶" : "Ⅱ"}</span>
      {paused ? "Resume logo carousel" : "Pause logo carousel"}
    </button>
  );
}
