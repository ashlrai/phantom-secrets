import { AbsoluteFill, useCurrentFrame, interpolate, spring, useVideoConfig, Sequence } from "remotion";

const BLUE = "#3b82f6";
const BLUE_B = "#60a5fa";
const GREEN = "#22c55e";
const RED = "#ef4444";
const BG = "#050508";
const S1 = "#0a0a12";
const S2 = "#101018";
const BORDER = "#1a1a2c";
const T1 = "#f5f5f7";
const T2 = "#a1a1b5";
const T3 = "#65657a";

const fontFamily = "'Inter', -apple-system, system-ui, sans-serif";
const mono = "'SF Mono', 'Fira Code', monospace";

// Typing animation helper
function useTyping(text, startFrame, charsPerFrame = 0.8) {
  const frame = useCurrentFrame();
  const elapsed = Math.max(0, frame - startFrame);
  const chars = Math.min(Math.floor(elapsed * charsPerFrame), text.length);
  return text.slice(0, chars);
}

// Fade in helper
function useFadeIn(startFrame, duration = 15) {
  const frame = useCurrentFrame();
  return interpolate(frame, [startFrame, startFrame + duration], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
}

function useSlideUp(startFrame, duration = 20) {
  const frame = useCurrentFrame();
  const opacity = interpolate(frame, [startFrame, startFrame + duration], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const y = interpolate(frame, [startFrame, startFrame + duration], [30, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return { opacity, transform: `translateY(${y}px)` };
}

// Terminal line component
function TermLine({ children, startFrame, style }) {
  const s = useSlideUp(startFrame, 12);
  return <div style={{ ...s, lineHeight: "2.2", ...style }}>{children}</div>;
}

export const PhantomDemo = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  return (
    <AbsoluteFill style={{ background: BG, fontFamily, color: T1 }}>
      {/* Subtle blue glow */}
      <div style={{
        position: "absolute", top: "-200px", left: "50%", width: "1000px", height: "800px",
        transform: "translateX(-50%)",
        background: "radial-gradient(ellipse at 50% 30%, rgba(59,130,246,0.06) 0%, transparent 70%)",
      }} />

      {/* ═══ Scene 1: Hero (frames 0-90) ═══ */}
      <Sequence from={0} durationInFrames={120}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <div style={{ ...useSlideUp(5, 25), fontSize: "82px", fontWeight: 900, letterSpacing: "-0.06em", lineHeight: 0.95, textAlign: "center" }}>
            Delegate everything
          </div>
          <div style={{ ...useSlideUp(12, 25), fontSize: "82px", fontWeight: 900, letterSpacing: "-0.06em", lineHeight: 0.95, color: BLUE_B, textAlign: "center", marginTop: "8px" }}>
            to AI.
          </div>
          <div style={{ ...useSlideUp(25, 20), fontSize: "22px", color: T2, marginTop: "32px", textAlign: "center", maxWidth: "600px", lineHeight: 1.7 }}>
            Your API keys work through AI agents without ever being exposed.
          </div>
          <div style={{ ...useSlideUp(40, 15), marginTop: "28px", display: "flex", gap: "12px" }}>
            <div style={{ padding: "12px 28px", background: BLUE, color: "#fff", borderRadius: "8px", fontSize: "17px", fontWeight: 600 }}>
              Get started
            </div>
            <div style={{ padding: "12px 28px", background: "transparent", color: T1, borderRadius: "8px", fontSize: "17px", fontWeight: 600, border: `1px solid ${BORDER}` }}>
              How it works
            </div>
          </div>
        </AbsoluteFill>
      </Sequence>

      {/* ═══ Scene 2: The Problem (frames 120-210) ═══ */}
      <Sequence from={120} durationInFrames={90}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 120px" }}>
          <div style={{ ...useSlideUp(0, 20), fontSize: "44px", fontWeight: 800, letterSpacing: "-0.04em", textAlign: "center", marginBottom: "24px" }}>
            You know the risk.
          </div>
          <div style={{ ...useSlideUp(10, 20), fontSize: "20px", color: T2, textAlign: "center", maxWidth: "600px", lineHeight: 1.8, marginBottom: "48px" }}>
            You paste API keys into Claude Code. You let Cursor read your .env.
            You know it's risky — but AI doing your work is worth it.
          </div>

          {/* Stats row */}
          <div style={{ ...useSlideUp(25, 20), display: "flex", gap: "2px", width: "100%", maxWidth: "800px", borderRadius: "14px", overflow: "hidden", border: `1px solid ${BORDER}` }}>
            <div style={{ flex: 1, background: S1, padding: "32px", textAlign: "center" }}>
              <div style={{ fontSize: "48px", fontWeight: 900, letterSpacing: "-0.04em" }}>39.6M</div>
              <div style={{ fontSize: "14px", color: T2, marginTop: "6px" }}>secrets leaked on GitHub in 2025</div>
            </div>
            <div style={{ flex: 1, background: S1, padding: "32px", textAlign: "center" }}>
              <div style={{ fontSize: "48px", fontWeight: 900, letterSpacing: "-0.04em" }}>2&times;</div>
              <div style={{ fontSize: "14px", color: T2, marginTop: "6px" }}>higher leak rate with AI commits</div>
            </div>
            <div style={{ flex: 1, background: S1, padding: "32px", textAlign: "center" }}>
              <div style={{ fontSize: "48px", fontWeight: 900, letterSpacing: "-0.04em" }}>+81%</div>
              <div style={{ fontSize: "14px", color: T2, marginTop: "6px" }}>YoY increase in AI key leaks</div>
            </div>
          </div>
        </AbsoluteFill>
      </Sequence>

      {/* ═══ Scene 3: Before/After (frames 210-320) ═══ */}
      <Sequence from={210} durationInFrames={110}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 100px" }}>
          <div style={{ ...useSlideUp(0, 20), fontSize: "44px", fontWeight: 800, letterSpacing: "-0.04em", textAlign: "center", marginBottom: "40px" }}>
            One command changes everything.
          </div>

          <div style={{ display: "flex", gap: "2px", width: "100%", maxWidth: "900px", borderRadius: "14px", overflow: "hidden", border: `1px solid ${BORDER}`, boxShadow: "0 32px 80px rgba(0,0,0,0.5)" }}>
            {/* Before */}
            <div style={{ ...useSlideUp(10, 20), flex: 1, background: S1 }}>
              <div style={{ padding: "14px 20px", fontSize: "12px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: RED, display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: RED }} /> Today — AI sees your real keys
              </div>
              <div style={{ padding: "4px 20px 20px", fontFamily: mono, fontSize: "15px", lineHeight: 2.2 }}>
                <span style={{ color: T3 }}># .env</span><br />
                <span style={{ color: T3 }}>OPENAI_API_KEY=</span><span style={{ color: RED }}>sk-proj-a8Kx9mR...real</span><br />
                <span style={{ color: T3 }}>STRIPE_SECRET=</span><span style={{ color: RED }}>sk_live_4eC39HJ...real</span><br />
                <span style={{ color: T3 }}>DATABASE_URL=</span><span style={{ color: RED }}>postgres://u:pass@db</span>
              </div>
            </div>

            {/* After */}
            <div style={{ ...useSlideUp(20, 20), flex: 1, background: S1 }}>
              <div style={{ padding: "14px 20px", fontSize: "12px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: BLUE_B, display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: BLUE_B }} /> With Phantom — keys stay safe
              </div>
              <div style={{ padding: "4px 20px 20px", fontFamily: mono, fontSize: "15px", lineHeight: 2.2 }}>
                <span style={{ color: T3 }}># .env</span><br />
                <span style={{ color: T3 }}>OPENAI_API_KEY=</span><span style={{ color: BLUE_B }}>phm_d9f1c157e32c...</span><br />
                <span style={{ color: T3 }}>STRIPE_SECRET=</span><span style={{ color: BLUE_B }}>phm_2ccb5a6ce675...</span><br />
                <span style={{ color: T3 }}>DATABASE_URL=</span><span style={{ color: BLUE_B }}>phm_99a8d2fe93c5...</span>
              </div>
            </div>
          </div>

          <div style={{ ...useSlideUp(35, 15), marginTop: "20px", fontSize: "14px", color: T2, display: "flex", alignItems: "center", gap: "8px", background: S2, border: `1px solid ${BORDER}`, borderRadius: "100px", padding: "8px 20px" }}>
            <span style={{ color: GREEN }}>&#10003;</span> AI uses your keys through a <strong style={{ color: T1 }}>local proxy</strong> — never sees real values
          </div>
        </AbsoluteFill>
      </Sequence>

      {/* ═══ Scene 4: Terminal Demo (frames 320-420) ═══ */}
      <Sequence from={320} durationInFrames={100}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 120px" }}>
          <div style={{ width: "100%", maxWidth: "760px", background: S1, border: `1px solid ${BORDER}`, borderRadius: "14px", overflow: "hidden", boxShadow: "0 32px 80px rgba(0,0,0,0.5)" }}>
            {/* Terminal bar */}
            <div style={{ display: "flex", alignItems: "center", gap: "6px", padding: "14px 18px", borderBottom: `1px solid ${BORDER}` }}>
              <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: RED, opacity: 0.45 }} />
              <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#eab308", opacity: 0.45 }} />
              <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: GREEN, opacity: 0.45 }} />
              <span style={{ marginLeft: "auto", fontFamily: mono, fontSize: "12px", color: T3 }}>~/my-app</span>
            </div>
            {/* Terminal body */}
            <div style={{ padding: "20px", fontFamily: mono, fontSize: "15px", lineHeight: 2.2 }}>
              <TermLine startFrame={5}><span style={{ color: T3 }}>$ </span><span>phantom init</span></TermLine>
              <TermLine startFrame={20}><span style={{ color: BLUE_B }}>-&gt;</span> <span style={{ color: T2 }}>Found 3 secret(s) to protect</span></TermLine>
              <TermLine startFrame={28}><span style={{ color: GREEN, fontWeight: 600 }}>ok</span> <span style={{ color: T2 }}>Rewrote .env with phantom tokens</span></TermLine>
              <TermLine startFrame={36}><span style={{ color: GREEN, fontWeight: 600 }}>done</span> <span style={{ color: T2 }}>3 secret(s) are now protected!</span></TermLine>
              <TermLine startFrame={50} style={{ height: "12px" }}> </TermLine>
              <TermLine startFrame={52}><span style={{ color: T3 }}>$ </span><span>phantom exec -- claude</span></TermLine>
              <TermLine startFrame={65}><span style={{ color: GREEN, fontWeight: 600 }}>ok</span> <span style={{ color: T2 }}>Proxy running on </span><span style={{ color: BLUE_B }}>127.0.0.1:54321</span></TermLine>
              <TermLine startFrame={73}><span style={{ color: BLUE_B }}>-&gt;</span> <span style={{ color: T2 }}>3 secret(s) proxied, 1 env var injected</span></TermLine>
              <TermLine startFrame={80}><span style={{ color: BLUE_B }}>-&gt;</span> <span style={{ color: T2 }}>Launching: </span><span style={{ color: BLUE_B }}>claude</span></TermLine>
            </div>
          </div>
        </AbsoluteFill>
      </Sequence>

      {/* ═══ Scene 5: CTA (frames 420-450) ═══ */}
      <Sequence from={420} durationInFrames={30}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <div style={{ ...useSlideUp(0, 20), fontSize: "52px", fontWeight: 900, letterSpacing: "-0.05em", textAlign: "center" }}>
            Let AI do the work.
          </div>
          <div style={{ ...useSlideUp(5, 20), fontSize: "52px", fontWeight: 900, letterSpacing: "-0.05em", color: BLUE_B, textAlign: "center" }}>
            Keep your keys safe.
          </div>
          <div style={{ ...useSlideUp(10, 15), marginTop: "28px", fontSize: "20px", color: T2 }}>
            phm.dev
          </div>
          <div style={{ ...useSlideUp(15, 15), marginTop: "20px", display: "flex", gap: "12px" }}>
            <div style={{ padding: "12px 28px", background: BLUE, color: "#fff", borderRadius: "8px", fontSize: "17px", fontWeight: 600 }}>
              Get started — it's free
            </div>
          </div>
        </AbsoluteFill>
      </Sequence>
    </AbsoluteFill>
  );
};
