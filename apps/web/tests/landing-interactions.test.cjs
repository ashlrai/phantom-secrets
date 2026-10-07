const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

function compile(name, localRequire, window, document) {
  const input = fs.readFileSync(path.join(__dirname, "../src/components/landing", name), "utf8");
  const output = ts.transpileModule(input, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022, esModuleInterop: true }, fileName: name,
  }).outputText;
  const exports = {};
  new Function("exports", "require", "window", "document", output)(exports, localRequire, window, document);
  return exports;
}
class Surface extends EventTarget {
  listeners = new Map();
  addEventListener(type, callback, options) {
    super.addEventListener(type, callback, options);
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(callback);
  }
  removeEventListener(type, callback, options) {
    super.removeEventListener(type, callback, options); this.listeners.get(type)?.delete(callback);
  }
  emit(type) { this.dispatchEvent(new Event(type)); }
  get listenerCount() { return [...this.listeners.values()].reduce((total, callbacks) => total + callbacks.size, 0); }
}
function carouselFixture({ hidden = false, reduced = false, intersection = true } = {}) {
  const window = new Surface(); const document = new Surface(); document.hidden = hidden;
  const preference = new Surface(); preference.matches = reduced;
  window.matchMedia = (query) => { assert.equal(query, "(prefers-reduced-motion: reduce)"); return preference; };
  const classes = new Set();
  const carousel = { classList: { toggle(name, enabled) { enabled ? classes.add(name) : classes.delete(name); }, add(name) { classes.add(name); } } };
  let observer;
  if (intersection) window.IntersectionObserver = class {
    constructor(callback) { this.callback = callback; this.disconnected = false; observer = this; }
    observe(target) { assert.equal(target, carousel); }
    disconnect() { this.disconnected = true; }
  };
  const { initializeCarouselMotion } = compile("carousel-motion.ts", require, window, document);
  return {
    window, document, preference, carousel,
    start(paused = false) { return initializeCarouselMotion(carousel, paused); },
    intersect(visible) { observer.callback([{ target: carousel, isIntersecting: visible }]); },
    reduced(value) { preference.matches = value; preference.emit("change"); },
    hidden(value) { document.hidden = value; document.emit("visibilitychange"); },
    get paused() { return classes.has("logo-marquee--paused"); }, get observer() { return observer; },
  };
}
test("carousel waits for intersection and suspends offscreen and in background tabs", () => {
  const f = carouselFixture(); const controller = f.start(); assert.equal(f.paused, true);
  f.intersect(true); assert.equal(f.paused, false); f.intersect(false); assert.equal(f.paused, true);
  f.intersect(true); assert.equal(f.paused, false); f.hidden(true); assert.equal(f.paused, true);
  f.intersect(true); assert.equal(f.paused, true); f.hidden(false); assert.equal(f.paused, false); controller.dispose();
});
test("manual pause survives viewport, visibility and live reduced-motion changes", () => {
  const f = carouselFixture(); const controller = f.start(); f.intersect(true); controller.setPaused(true);
  f.intersect(false); f.hidden(true); f.reduced(true); f.intersect(true); f.hidden(false); f.reduced(false);
  assert.equal(f.paused, true, "environment recovery must not undo manual pause");
  controller.setPaused(false); assert.equal(f.paused, false); f.reduced(true); assert.equal(f.paused, true);
  controller.setPaused(false); assert.equal(f.paused, true, "manual resume cannot override reduced motion");
  f.reduced(false); assert.equal(f.paused, false); controller.dispose();
});
test("initial hidden/reduced state and a persisted manual choice remain paused on remount", () => {
  const f = carouselFixture({ hidden: true, reduced: true }); let controller = f.start(true); f.intersect(true);
  f.hidden(false); f.reduced(false); assert.equal(f.paused, true);
  controller.dispose(); controller = f.start(true); f.intersect(true); assert.equal(f.paused, true);
  controller.setPaused(false); assert.equal(f.paused, false); controller.dispose();
});
test("pagehide/pageshow preserves both viewport state and manual choice", () => {
  const f = carouselFixture(); const controller = f.start(); f.intersect(true);
  f.window.emit("pagehide"); assert.equal(f.paused, true); f.window.emit("pageshow"); assert.equal(f.paused, false);
  controller.setPaused(true); f.window.emit("pagehide"); f.window.emit("pageshow"); assert.equal(f.paused, true);
  controller.setPaused(false); f.intersect(false); f.window.emit("pageshow"); assert.equal(f.paused, true); controller.dispose();
});
test("cleanup removes subscriptions and stale callbacks cannot restart motion", () => {
  const f = carouselFixture(); const controller = f.start(); f.intersect(true);
  assert.equal(f.window.listenerCount, 2); assert.equal(f.document.listenerCount, 1); assert.equal(f.preference.listenerCount, 1);
  controller.dispose(); assert.equal(f.observer.disconnected, true);
  assert.equal(f.window.listenerCount + f.document.listenerCount + f.preference.listenerCount, 0);
  f.intersect(true); f.hidden(false); f.reduced(false); f.window.emit("pageshow"); controller.setPaused(false);
  assert.equal(f.paused, true); controller.dispose();
});
test("without IntersectionObserver visibility and reduced motion still control the carousel", () => {
  const f = carouselFixture({ intersection: false }); const controller = f.start(); assert.equal(f.paused, false);
  f.hidden(true); assert.equal(f.paused, true); f.hidden(false); assert.equal(f.paused, false);
  f.reduced(true); assert.equal(f.paused, true); controller.dispose();
});
function navigationFixture(pathname, menuOpen = false) {
  const window = new Surface(); window.scrollY = 0; window.location = { hash: "", replace() { assert.fail("not a legacy bookmark"); } };
  const effects = []; const stateUpdates = []; const trigger = { focusCount: 0, focus() { this.focusCount++; } }; let stateIndex = 0;
  const hooks = { ...React,
    useState(initial) { const index = stateIndex++; return [index === 1 ? menuOpen : initial, (value) => stateUpdates.push([index, value])]; },
    useEffect(effect) { effects.push(effect); }, useRef() { return { current: trigger }; },
  };
  const localRequire = (name) => {
    if (name === "react") return hooks;
    if (name === "next/navigation") return { usePathname: () => pathname };
    if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
    if (name === "next/image") return { __esModule: true, default: ({ priority, ...props }) => React.createElement("img", props) };
    if (name === "@/lib/posthog") return { capturePostHog: async () => {} };
    if (name === "@/lib/legacy-secrets-fragment") return { legacySecretsDestination: () => null };
    if (name === "./Icons") return { Github: () => React.createElement("svg") };
    return require(name);
  };
  const { Nav } = compile("Nav.tsx", localRequire, window, undefined);
  return { element: Nav(), window, effects, stateUpdates, trigger };
}
test("rendered desktop and mobile GitHub links choose the same correct product source", () => {
  for (const [pathname, repository, label] of [["/", "ashlr-hub", "Phantom workbench"], ["/secrets", "phantom-secrets", "Phantom Secrets"], ["/docs/getting-started", "phantom-secrets", "Phantom Secrets"]]) {
    const markup = renderToStaticMarkup(navigationFixture(pathname).element);
    const links = [...markup.matchAll(/<a\b[^>]*>[^]*?<\/a>/g)].map(([link]) => link).filter((link) => link.includes("View on GitHub"));
    assert.equal(links.length, 2, pathname);
    for (const link of links) {
      assert.ok(link.includes(`href="https://github.com/ashlrai/${repository}"`), pathname);
      assert.ok(link.includes(`aria-label="View ${label} source on GitHub"`), pathname);
    }
  }
});
test("Escape returns focus from the inline mobile disclosure and its listener is cleaned up", () => {
  const f = navigationFixture("/secrets", true); const cleanups = f.effects.map((effect) => effect()).filter(Boolean);
  const escape = new Event("keydown"); Object.defineProperty(escape, "key", { value: "Escape" }); f.window.dispatchEvent(escape);
  assert.ok(f.stateUpdates.some(([index, value]) => index === 1 && value === false)); assert.equal(f.trigger.focusCount, 1);
  cleanups.forEach((cleanup) => cleanup()); assert.equal(f.window.listenerCount, 0);
  f.window.dispatchEvent(escape); assert.equal(f.trigger.focusCount, 1);
});

test("batched intersection crossings use the latest visibility instead of an earlier visible entry", () => {
  const f = carouselFixture(); const controller = f.start();
  f.observer.callback([{ target: f.carousel, isIntersecting: true }, { target: f.carousel, isIntersecting: false }]);
  assert.equal(f.paused, true);
  f.observer.callback([{ target: f.carousel, isIntersecting: false }, { target: f.carousel, isIntersecting: true }]);
  assert.equal(f.paused, false); controller.dispose();
});

test("the actual carousel button retains rapid manual choices and disposes its controller", () => {
  const f = carouselFixture(); f.document.getElementById = (id) => { assert.equal(id, "test-carousel"); return f.carousel; };
  const effects = []; const updates = []; const refs = [];
  const hooks = { ...React, useState: (initial) => [initial, (next) => updates.push(next)],
    useRef: (initial) => { const ref = { current: initial }; refs.push(ref); return ref; },
    useEffect: (effect) => effects.push(effect),
  };
  const initialize = compile("carousel-motion.ts", require, f.window, f.document);
  const localRequire = (name) => name === "react" ? hooks : name === "./carousel-motion" ? initialize : require(name);
  const { CarouselPauseButton } = compile("CarouselPauseButton.tsx", localRequire, f.window, f.document);
  const element = CarouselPauseButton({ controls: "test-carousel" });
  const dispose = effects[0](); f.intersect(true); assert.equal(f.paused, false);
  element.props.onClick(); assert.equal(f.paused, true);
  element.props.onClick(); assert.equal(f.paused, false, "two clicks before a rerender must not read stale state");
  assert.deepEqual(updates, [true, false]); assert.equal(refs[0].current, false);
  dispose(); assert.equal(refs[1].current, null); assert.equal(f.paused, true);
  element.props.onClick(); assert.deepEqual(updates, [true, false]);
});

test("an already-handled Escape does not close the disclosure or steal focus", () => {
  const f = navigationFixture("/secrets", true); const cleanups = f.effects.map((effect) => effect()).filter(Boolean);
  const escape = new Event("keydown", { cancelable: true }); Object.defineProperty(escape, "key", { value: "Escape" });
  escape.preventDefault(); f.window.dispatchEvent(escape);
  assert.equal(f.trigger.focusCount, 0);
  assert.equal(f.stateUpdates.some(([index, value]) => index === 1 && value === false), false);
  cleanups.forEach((cleanup) => cleanup());
});
