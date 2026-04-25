# Hero Media Assets — Generation Brief

The hero is a scroll-driven cinematic video. Until you drop the assets in
`apps/web/public/hero/`, the page renders an animated CSS gradient fallback
so it isn't broken.

## Files the hero looks for

```
apps/web/public/hero/
  loop.mp4     ← required (H.264, 16:9, 1920×1080, 8–10s, ~5 MB target)
  loop.webm    ← optional (VP9 fallback for size)
  poster.jpg   ← required (first frame, 1920×1080, ~150 KB)
```

The page does a `HEAD /hero/loop.mp4` on mount. If 200, it swaps the
gradient backdrop for the video and wires scroll-driven `currentTime`.

## Visual direction (read this before prompting)

- **Mood:** cinematic, magical, calm, premium. Apple Vision Pro keynote
  meets Dune cinematography. NOT a generic explainer.
- **Palette:** deep navy (#050508), sapphire (#3b82f6), soft cyan
  (#60a5fa), single warm accent inside the vault (#f5b041 / amber).
- **Center subject:** a translucent crystalline cube ("the vault") with a
  small molten amber star inside it.
- **Orbit:** 3 ghostly translucent slabs labeled with `phm_` tokens,
  drifting around the vault.
- **Background:** infinite navy void, dust particles catching faint light,
  volumetric beams from below.
- **Camera:** locked, no cuts. Only contents move.
- **Composition:** 16:9, vault dead-center, tokens 3 around it offset to
  form the rule-of-thirds intersections at end frame.

## Why this design

The story arc (which the scroll plays through):
1. Vault sealed, holding your real key — the inner amber star is
   contained, glowing
2. Phantom tokens spin off from the vault, drifting outward
3. Tokens flow toward an abstract AI constellation in the upper-right —
   they're being passed safely to AI
4. The vault stays sealed and intact behind everything

Visually it says: real keys never leave; AI gets phantoms; this is safe.

---

## Step 1 — Generate the **start frame** (Grok Imagine)

> Cinematic widescreen composition, 16:9, photorealistic ultra-detailed
> 8K. Center: a single translucent crystalline cube, ~60% transparent,
> with iridescent surface refractions in deep sapphire blue and faint
> violet. Inside the cube: a small sphere of molten amber-gold light,
> visibly contained, like a captured star. Three ghostly translucent
> rectangular plaques floating close to the cube at slightly different
> depths, each faintly displaying the text `phm_a8f2c4d9` in soft cyan
> monospace font. Background: infinite deep navy void with subtle
> floating dust particles catching faint blue light. Volumetric light
> beams from below the cube. Soft lens flare upper right. Style: Apple
> Vision Pro keynote, Dune cinematography, glassmorphic, dreamlike.
> Color palette: deep navy, sapphire blue, soft cyan, single
> golden-amber accent. Soft bokeh background, sharp foreground.

Save as `start.jpg` (1920×1080).

## Step 2 — Generate the **end frame** (Grok Imagine)

> Same cinematic widescreen composition, 16:9, photorealistic ultra-
> detailed 8K. Same translucent crystalline cube at center frame,
> sealed, glowing softly with the inner amber star steady and confident.
> The three phantom token plaques (`phm_a8f2c4d9` text in soft cyan
> monospace) have drifted outward into a graceful constellation in the
> upper-right region of the frame, where they meet a neural-network
> constellation of glowing light nodes pulsing softly (representing AI).
> A soft sapphire beam of light connects the constellation to the
> phantom tokens — they are being passed safely. Background unchanged:
> deep navy void, dust particles, volumetric beams from below. Style
> and palette identical to the start frame: deep navy, sapphire,
> cyan, amber accent. Mood: peaceful, balanced, magical. Glassmorphic
> refractive surfaces.

Save as `end.jpg` (1920×1080).

> **Important about text in generated images:** AI image gen often
> mangles text. The `phm_` labels can be a bit garbled — that's fine,
> they read as "tokens" at video distance. If they're badly broken,
> regenerate with the text removed and we'll add CSS overlays later.

## Step 3 — Generate the **video** connecting them

Use Runway Gen-3, Kling 2.0, or Pika. Upload `start.jpg` as the start
keyframe and `end.jpg` as the end keyframe (both tools support this).
Prompt:

> 8-second seamless cinematic shot. Camera fixed; only the scene
> contents move. The three translucent phantom token plaques around
> the central crystalline cube begin drifting in a graceful spiral
> outward, eventually arranging into a constellation in the upper-
> right corner. As they arrive there, an abstract AI neural-network
> constellation of soft light nodes fades in to meet them. The amber
> star inside the cube transitions from anxious pulsing to a confident
> steady glow. Volumetric light beams from below strengthen subtly.
> Background dust particles drift gently. Style: Apple Vision Pro,
> Dune, glassmorphic, dreamlike, photorealistic. Deep navy + sapphire
> + cyan palette, single amber accent. 24fps, 1920×1080, 16:9.

## Step 4 — Encode for the web

After the video tool delivers your raw output:

```bash
# Crop/scale to exactly 1920x1080, target ~5 MB H.264
ffmpeg -i raw.mp4 \
  -vf "scale=1920:1080:force_original_aspect_ratio=increase,crop=1920:1080" \
  -c:v libx264 -preset slow -crf 23 -profile:v high -pix_fmt yuv420p \
  -movflags +faststart -an \
  apps/web/public/hero/loop.mp4

# Optional: VP9 WebM for ~30% smaller payload on modern browsers
ffmpeg -i raw.mp4 \
  -vf "scale=1920:1080:force_original_aspect_ratio=increase,crop=1920:1080" \
  -c:v libvpx-vp9 -b:v 0 -crf 32 -row-mt 1 -an \
  apps/web/public/hero/loop.webm

# Poster (first frame)
ffmpeg -i apps/web/public/hero/loop.mp4 -vframes 1 -q:v 3 \
  apps/web/public/hero/poster.jpg
```

`-movflags +faststart` is mandatory — it puts the MP4 moov atom at the
start so the browser can begin streaming + seeking immediately.

## Step 5 — Ship it

```
git add apps/web/public/hero/loop.mp4 apps/web/public/hero/poster.jpg
git add apps/web/public/hero/loop.webm   # if you made one
git commit -m "feat(web): hero video assets"
git push
```

Vercel auto-deploy will pick it up. The hero will swap from the gradient
fallback to the video on next load.

---

## Future upgrade — frame-sequence scrubbing

If after shipping the `<video>` version, scroll-scrubbing on iOS Safari
feels jittery (it usually does on long MP4s — Safari only seeks cleanly
to keyframes), upgrade to a frame sequence:

1. Export 90 frames from the video: `ffmpeg -i loop.mp4 -vf "fps=10"
   public/hero/frames/frame-%03d.webp`
2. Replace the `<video>` in `Hero.tsx` with a `<canvas>` + Image
   preload loop that draws the indexed frame based on scroll progress.
3. ~30 MB total payload but completely silky scrubbing.

I can wire that up after assets land if Safari scrubbing isn't smooth.
