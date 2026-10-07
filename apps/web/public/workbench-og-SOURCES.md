# Phantom workbench social card

`workbench-og.png` is the root workbench's 1200×630 social image. The separate Secrets card `og-image.png` stays unchanged for `/secrets` and its product pages.

Reproduce the card from the locked repository dependencies with `node apps/web/scripts/generate-workbench-og.mjs` (or from `apps/web`, `node scripts/generate-workbench-og.mjs`). The script also writes the reviewable SVG source. It has no network input and uses the exact first-party blue ghost from `public/phantom-world/phantom-mark.svg`; its existing source/license notice remains adjacent. The Ghost source was copied from Ashlr Hub commit `a2de40342e08e6e3e1c8a4e12a5ee45f37aad141`.

Sharp 0.35.5/libvips renders the SVG into a fixed PNG. Regeneration uses the host's Arial/Helvetica fallback font; use the checked-in PNG for byte-identical publication rather than assuming different hosts have identical system fonts. This is an illustrated product card, not a running-session screenshot or a claim that every provider is connected.
