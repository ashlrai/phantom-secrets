/** Suspend invisible motion without replacing the user's persistent choice. */
export function initializeCarouselMotion(carousel: HTMLElement, initiallyPaused = false) {
  let userPaused = initiallyPaused;
  let inView = !("IntersectionObserver" in window);
  let pageHidden = document.hidden;
  let disposed = false;
  const preference = window.matchMedia("(prefers-reduced-motion: reduce)");
  const update = () => {
    if (!disposed) {
      carousel.classList.toggle("logo-marquee--paused", userPaused || pageHidden || !inView || preference.matches);
    }
  };
  const visibilityChanged = () => { pageHidden = document.hidden; update(); };
  const pageHiddenChanged = () => { pageHidden = true; update(); };
  const pageShown = () => { pageHidden = document.hidden; update(); };
  const observer = "IntersectionObserver" in window
    ? new window.IntersectionObserver((entries) => {
      // A callback can batch several crossings; the latest entry owns visibility.
      for (const entry of entries) if (entry.target === carousel) inView = entry.isIntersecting;
      update();
    })
    : null;
  observer?.observe(carousel);
  preference.addEventListener("change", update);
  document.addEventListener("visibilitychange", visibilityChanged);
  window.addEventListener("pagehide", pageHiddenChanged);
  window.addEventListener("pageshow", pageShown);
  update();

  return {
    setPaused(paused: boolean) { userPaused = paused; update(); },
    dispose() {
      // Hold motion while unmounted or before a replacement controller mounts.
      carousel.classList.add("logo-marquee--paused");
      disposed = true;
      observer?.disconnect();
      preference.removeEventListener("change", update);
      document.removeEventListener("visibilitychange", visibilityChanged);
      window.removeEventListener("pagehide", pageHiddenChanged);
      window.removeEventListener("pageshow", pageShown);
    },
  };
}
