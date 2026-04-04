import { AbsoluteFill, useCurrentFrame, interpolate, Sequence } from "remotion";

const BLUE = "#3b82f6";
const BLUE_B = "#60a5fa";
const GREEN = "#22c55e";
const RED = "#ef4444";
const YELLOW = "#eab308";
const BG = "#050508";
const S1 = "#0a0a12";
const BORDER = "#1a1a2c";
const T1 = "#f5f5f7";
const T2 = "#a1a1b5";
const T3 = "#65657a";
const CYAN = "#22d3ee";

const fontFamily = "'Inter', -apple-system, system-ui, sans-serif";
const mono = "'SF Mono', 'Fira Code', monospace";

function useSlideUp(startFrame, duration = 15) {
  const frame = useCurrentFrame();
  const opacity = interpolate(frame, [startFrame, startFrame + duration], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const y = interpolate(frame, [startFrame, startFrame + duration], [30, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return { opacity, transform: `translateY(${y}px)` };
}

function TermLine({ children, startFrame, style }) {
  const s = useSlideUp(startFrame, 10);
  return <div style={{ ...s, lineHeight: "2.1", ...style }}>{children}</div>;
}

function Prompt({ children }) {
  return <><span style={{ color: T3 }}>$ </span><span>{children}</span></>;
}

function Ok({ children }) {
  return <><span style={{ color: GREEN, fontWeight: 600 }}>ok</span> <span style={{ color: T2 }}>{children}</span></>;
}

function Arrow({ children, color }) {
  return <><span style={{ color: color || BLUE_B }}>-&gt;</span> <span style={{ color: T2 }}>{children}</span></>;
}

function Plus({ children }) {
  return <><span style={{ color: CYAN, fontWeight: 600 }}>   +</span> <span style={{ fontWeight: 600 }}>{children}</span></>;
}

function Warn({ children }) {
  return <><span style={{ color: YELLOW, fontWeight: 600 }}>!</span> <span style={{ color: T2 }}>{children}</span></>;
}

function Terminal({ title, children }) {
  return (
    <div style={{
      width: "100%", maxWidth: "800px",
      background: S1, border: `1px solid ${BORDER}`, borderRadius: "14px",
      overflow: "hidden", boxShadow: "0 32px 80px rgba(0,0,0,0.5)",
    }}>
      <div style={{
        display: "flex", alignItems: "center", gap: "6px",
        padding: "14px 18px", borderBottom: `1px solid ${BORDER}`,
      }}>
        <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: RED, opacity: 0.45 }} />
        <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: YELLOW, opacity: 0.45 }} />
        <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: GREEN, opacity: 0.45 }} />
        <span style={{ marginLeft: "auto", fontFamily: mono, fontSize: "12px", color: T3 }}>{title || "~/my-app"}</span>
      </div>
      <div style={{ padding: "20px", fontFamily: mono, fontSize: "15px", lineHeight: 2.1 }}>
        {children}
      </div>
    </div>
  );
}

function SceneHeading({ text, startFrame }) {
  const s = useSlideUp(startFrame || 0, 15);
  return (
    <div style={{ ...s, fontSize: "16px", fontWeight: 600, letterSpacing: "0.12em", textTransform: "uppercase", color: BLUE_B, marginBottom: "20px" }}>
      {text}
    </div>
  );
}

function Badge({ text, color, startFrame }) {
  const s = useSlideUp(startFrame, 12);
  return (
    <div style={{
      ...s, marginTop: "18px", fontSize: "14px", color: T2,
      display: "flex", alignItems: "center", gap: "8px",
      background: "#0a0a12", border: `1px solid ${BORDER}`,
      borderRadius: "100px", padding: "8px 20px",
    }}>
      <span style={{ color: color || GREEN }}>&#10003;</span> {text}
    </div>
  );
}


// TOTAL: 1350 frames = 45 seconds @ 30fps
export const PhantomDemo = () => {
  const frame = useCurrentFrame();

  return (
    <AbsoluteFill style={{ background: BG, fontFamily, color: T1 }}>
      {/* Ambient blue glow */}
      <div style={{
        position: "absolute", top: "-200px", left: "50%", width: "1000px", height: "800px",
        transform: "translateX(-50%)",
        background: "radial-gradient(ellipse at 50% 30%, rgba(59,130,246,0.06) 0%, transparent 70%)",
        zIndex: 0,
      }} />

      {/* === Scene 1: TITLE CARD (0-75, 2.5s) === */}
      <Sequence from={0} durationInFrames={75}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", zIndex: 1 }}>
          <div style={{ ...useSlideUp(0, 12), fontSize: "18px", color: BLUE_B, letterSpacing: "0.2em", fontWeight: 600, marginBottom: "16px" }}>
            P H A N T O M
          </div>
          <div style={{ ...useSlideUp(5, 15), fontSize: "68px", fontWeight: 900, letterSpacing: "-0.05em", textAlign: "center", lineHeight: 1 }}>
            One command.
          </div>
          <div style={{ ...useSlideUp(10, 15), fontSize: "68px", fontWeight: 900, letterSpacing: "-0.05em", textAlign: "center", lineHeight: 1, color: BLUE_B, marginTop: "4px" }}>
            Keys safe forever.
          </div>
          <div style={{ ...useSlideUp(20, 12), marginTop: "24px", fontSize: "18px", color: T2, textAlign: "center", maxWidth: "550px" }}>
            Your AI codes with your keys — without ever seeing them.
          </div>

          {/* Fade to black */}
          <div style={{
            position: "absolute", inset: 0, background: BG, zIndex: 10,
            opacity: interpolate(frame, [60, 75], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
          }} />
        </AbsoluteFill>
      </Sequence>

      {/* === Scene 2: THE PROBLEM — real .env (75-225, 5s) === */}
      <Sequence from={75} durationInFrames={150}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 100px", zIndex: 1 }}>
          <div style={{ ...useSlideUp(0, 15), fontSize: "40px", fontWeight: 800, letterSpacing: "-0.04em", textAlign: "center", marginBottom: "32px" }}>
            Your <span style={{ color: RED }}>.env</span> is an open book.
          </div>

          <Terminal title="~/.env">
            <TermLine startFrame={10}><span style={{ color: T3 }}># Every AI agent can read these</span></TermLine>
            <TermLine startFrame={18}><span style={{ color: T3 }}>OPENAI_API_KEY=</span><span style={{ color: RED }}>sk-proj-a8Kx9mR3...real</span></TermLine>
            <TermLine startFrame={24}><span style={{ color: T3 }}>STRIPE_SECRET=</span><span style={{ color: RED }}>sk_live_4eC39HJ...real</span></TermLine>
            <TermLine startFrame={30}><span style={{ color: T3 }}>DATABASE_URL=</span><span style={{ color: RED }}>postgres://user:pass@db</span></TermLine>
            <TermLine startFrame={36}><span style={{ color: T3 }}>NEXT_PUBLIC_APP_URL=</span><span style={{ color: T2 }}>http://localhost:3000</span></TermLine>
            <TermLine startFrame={42}><span style={{ color: T3 }}>NEXT_PUBLIC_SUPABASE_ANON_KEY=</span><span style={{ color: T2 }}>eyJhbGci...</span></TermLine>
          </Terminal>

          <Badge text="Claude, Cursor, Codex — all read .env directly" color={RED} startFrame={55} />
        </AbsoluteFill>
      </Sequence>

      {/* === Scene 3: SMART INIT — public key awareness (225-450, 7.5s) === */}
      <Sequence from={225} durationInFrames={225}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 100px", zIndex: 1 }}>
          <SceneHeading text="Smart Init" startFrame={0} />

          <Terminal>
            <TermLine startFrame={8}><Prompt>phantom init</Prompt></TermLine>
            <TermLine startFrame={20}><Arrow>Reading .env...</Arrow></TermLine>
            <TermLine startFrame={30}><Arrow>Found 3 secret(s) to protect:</Arrow></TermLine>
            <TermLine startFrame={38}><Plus>OPENAI_API_KEY</Plus></TermLine>
            <TermLine startFrame={44}><Plus>STRIPE_SECRET</Plus></TermLine>
            <TermLine startFrame={50}><Plus>DATABASE_URL</Plus></TermLine>
            <TermLine startFrame={62} style={{ height: "8px" }}> </TermLine>
            <TermLine startFrame={64}><Arrow>Skipping 2 public key(s) (safe for browser bundles):</Arrow></TermLine>
            <TermLine startFrame={72}><span style={{ color: T3 }}>   · NEXT_PUBLIC_APP_URL</span></TermLine>
            <TermLine startFrame={78}><span style={{ color: T3 }}>   · NEXT_PUBLIC_SUPABASE_ANON_KEY</span></TermLine>
            <TermLine startFrame={90} style={{ height: "8px" }}> </TermLine>
            <TermLine startFrame={92}><span style={{ color: GREEN, fontWeight: 600 }}>   +</span> <span style={{ fontWeight: 600 }}>OPENAI_API_KEY</span> <span style={{ color: T3 }}>-&gt;</span> <span style={{ color: T3 }}>phm_d9f1c157...</span></TermLine>
            <TermLine startFrame={100}><span style={{ color: GREEN, fontWeight: 600 }}>   +</span> <span style={{ fontWeight: 600 }}>STRIPE_SECRET</span> <span style={{ color: T3 }}>-&gt;</span> <span style={{ color: T3 }}>phm_2ccb5a6c...</span></TermLine>
            <TermLine startFrame={108}><span style={{ color: GREEN, fontWeight: 600 }}>   +</span> <span style={{ fontWeight: 600 }}>DATABASE_URL</span> <span style={{ color: T3 }}>-&gt;</span> <span style={{ color: T3 }}>phm_99a8d2fe...</span></TermLine>
            <TermLine startFrame={120}><Ok>Rewrote .env with phantom tokens</Ok></TermLine>
            <TermLine startFrame={130}><span style={{ color: GREEN, fontWeight: 600 }}>done</span> <span style={{ color: T2 }}>3 secret(s) protected, 2 public key(s) untouched</span></TermLine>
          </Terminal>

          <Badge text="NEXT_PUBLIC_*, VITE_*, EXPO_PUBLIC_* left untouched" startFrame={145} />
        </AbsoluteFill>
      </Sequence>

      {/* === Scene 4: PHANTOM WRAP (450-600, 5s) === */}
      <Sequence from={450} durationInFrames={150}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 100px", zIndex: 1 }}>
          <SceneHeading text="Zero-Friction Scripts" startFrame={0} />

          <Terminal>
            <TermLine startFrame={8}><Prompt>phantom wrap</Prompt></TermLine>
            <TermLine startFrame={22}><span style={{ color: CYAN, fontWeight: 600 }}>   +</span> <span style={{ fontWeight: 600 }}>dev</span> <span style={{ color: T3 }}>-&gt; wrapped with phantom exec</span></TermLine>
            <TermLine startFrame={30}><span style={{ color: CYAN, fontWeight: 600 }}>   +</span> <span style={{ fontWeight: 600 }}>build</span> <span style={{ color: T3 }}>-&gt; wrapped with phantom exec</span></TermLine>
            <TermLine startFrame={38}><span style={{ color: CYAN, fontWeight: 600 }}>   +</span> <span style={{ fontWeight: 600 }}>deploy</span> <span style={{ color: T3 }}>-&gt; wrapped with phantom exec</span></TermLine>
            <TermLine startFrame={50} style={{ height: "8px" }}> </TermLine>
            <TermLine startFrame={52}><Ok>Wrapped 3 script(s) in package.json</Ok></TermLine>
            <TermLine startFrame={60}><Arrow>Original scripts saved as <span style={{ color: CYAN }}>*:raw</span></Arrow></TermLine>
            <TermLine startFrame={72} style={{ height: "8px" }}> </TermLine>
            <TermLine startFrame={74}><span style={{ color: T3 }}># Now just use npm as usual:</span></TermLine>
            <TermLine startFrame={82}><Prompt>npm run dev</Prompt></TermLine>
            <TermLine startFrame={92}><Ok>Proxy running on <span style={{ color: BLUE_B }}>127.0.0.1:54321</span></Ok></TermLine>
          </Terminal>

          <Badge text="No more phantom exec prefix — just npm run dev" startFrame={105} />
        </AbsoluteFill>
      </Sequence>

      {/* === Scene 5: RESPONSE SCRUBBING (600-810, 7s) === */}
      <Sequence from={600} durationInFrames={210}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 80px", zIndex: 1 }}>
          <SceneHeading text="Response Scrubbing" startFrame={0} />

          <div style={{ ...useSlideUp(8, 15), fontSize: "28px", fontWeight: 700, letterSpacing: "-0.03em", textAlign: "center", marginBottom: "28px" }}>
            The proxy protects <span style={{ color: BLUE_B }}>both directions</span>.
          </div>

          <div style={{ display: "flex", gap: "2px", width: "100%", maxWidth: "940px", borderRadius: "14px", overflow: "hidden", border: `1px solid ${BORDER}`, boxShadow: "0 32px 80px rgba(0,0,0,0.5)" }}>
            {/* Outbound */}
            <div style={{ ...useSlideUp(18, 18), flex: 1, background: S1 }}>
              <div style={{ padding: "14px 20px", fontSize: "12px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: BLUE_B, display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "16px" }}>&#8593;</span> Request (outbound)
              </div>
              <div style={{ padding: "4px 20px 20px", fontFamily: mono, fontSize: "14px", lineHeight: 2 }}>
                <span style={{ color: T3 }}>Authorization:</span><br />
                <span style={{ color: T3 }}>  </span><span style={{ color: T3, textDecoration: "line-through" }}>phm_d9f1c157...</span><br />
                <span style={{ color: T3 }}>  </span><span style={{ color: GREEN }}>sk-proj-a8Kx9...</span><br />
                <span style={{ color: T3, fontSize: "12px" }}>Token swapped for real key</span>
              </div>
            </div>

            {/* Inbound */}
            <div style={{ ...useSlideUp(35, 18), flex: 1, background: S1 }}>
              <div style={{ padding: "14px 20px", fontSize: "12px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: GREEN, display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "16px" }}>&#8595;</span> Response (inbound)
              </div>
              <div style={{ padding: "4px 20px 20px", fontFamily: mono, fontSize: "14px", lineHeight: 2 }}>
                <span style={{ color: T3 }}>API returned:</span><br />
                <span style={{ color: T3 }}>  </span><span style={{ color: RED, textDecoration: "line-through" }}>{"\""}api_key{"\""}:{"\""} sk-proj-a8...</span><br />
                <span style={{ color: T3 }}>  </span><span style={{ color: GREEN }}>{"\""}api_key{"\""}:{"\""} phm_d9f1c...</span><br />
                <span style={{ color: T3, fontSize: "12px" }}>Real secret scrubbed from response</span>
              </div>
            </div>
          </div>

          <Badge text="AI never sees a real secret — even if the API echoes it back" startFrame={60} />
        </AbsoluteFill>
      </Sequence>

      {/* === Scene 6: PHANTOM WATCH (810-960, 5s) === */}
      <Sequence from={810} durationInFrames={150}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 100px", zIndex: 1 }}>
          <SceneHeading text="Auto-Detect New Secrets" startFrame={0} />

          <Terminal>
            <TermLine startFrame={8}><Prompt>phantom watch --auto</Prompt></TermLine>
            <TermLine startFrame={18}><Arrow>Watching for new secrets in: <span style={{ color: CYAN }}>.env, .env.local</span></Arrow></TermLine>
            <TermLine startFrame={26}><span style={{ color: T3 }}>   </span><Warn>Auto-protect mode enabled</Warn></TermLine>
            <TermLine startFrame={34}><span style={{ color: T3 }}>   Press Ctrl+C to stop.</span></TermLine>
            <TermLine startFrame={50} style={{ height: "8px" }}> </TermLine>
            <TermLine startFrame={52}><Warn>Detected 1 unprotected secret(s) in <span style={{ color: CYAN }}>.env</span>:</Warn></TermLine>
            <TermLine startFrame={60}><span style={{ color: CYAN, fontWeight: 600 }}>   +</span> <span style={{ fontWeight: 600 }}>ANTHROPIC_API_KEY</span></TermLine>
            <TermLine startFrame={72}><span style={{ color: T3 }}>   </span><Ok>Auto-protected 1 secret(s)</Ok></TermLine>
          </Terminal>

          <Badge text="Add a key to .env — phantom protects it instantly" startFrame={85} />
        </AbsoluteFill>
      </Sequence>

      {/* === Scene 7: DOCTOR --FIX (960-1140, 6s) === */}
      <Sequence from={960} durationInFrames={180}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 100px", zIndex: 1 }}>
          <SceneHeading text="Auto-Remediation" startFrame={0} />

          <Terminal>
            <TermLine startFrame={8}><Prompt>phantom doctor --fix</Prompt></TermLine>
            <TermLine startFrame={18}><span style={{ fontWeight: 700, textDecoration: "underline" }}>Phantom Doctor</span></TermLine>
            <TermLine startFrame={28} style={{ height: "8px" }}> </TermLine>
            <TermLine startFrame={30}><span style={{ color: GREEN }}>  pass</span> <span style={{ color: T2 }}>.phantom.toml found</span></TermLine>
            <TermLine startFrame={36}><span style={{ color: GREEN }}>  pass</span> <span style={{ color: T2 }}>Config valid (project: 3a7f2c91)</span></TermLine>
            <TermLine startFrame={42}><span style={{ color: GREEN }}>  pass</span> <span style={{ color: T2 }}>4 secret(s) in vault</span></TermLine>
            <TermLine startFrame={48}><span style={{ color: GREEN }}>  pass</span> <span style={{ color: T2 }}>.env has 6 entries, all protected</span></TermLine>
            <TermLine startFrame={54}><span style={{ color: YELLOW }}>  warn</span> <span style={{ color: T2 }}>.env is NOT in .gitignore</span></TermLine>
            <TermLine startFrame={60}><span style={{ color: T3 }}>       </span><span style={{ color: GREEN }}>Fixed:</span> <span style={{ color: T2 }}>Added .env to .gitignore</span></TermLine>
            <TermLine startFrame={68}><span style={{ color: YELLOW }}>  warn</span> <span style={{ color: T2 }}>No pre-commit hook installed</span></TermLine>
            <TermLine startFrame={74}><span style={{ color: T3 }}>       </span><span style={{ color: GREEN }}>Fixed:</span> <span style={{ color: T2 }}>Installed pre-commit hook</span></TermLine>
            <TermLine startFrame={82}><span style={{ color: YELLOW }}>  warn</span> <span style={{ color: T2 }}>No .env.example</span></TermLine>
            <TermLine startFrame={88}><span style={{ color: T3 }}>       </span><span style={{ color: GREEN }}>Fixed:</span> <span style={{ color: T2 }}>Generated .env.example</span></TermLine>
            <TermLine startFrame={100} style={{ height: "8px" }}> </TermLine>
            <TermLine startFrame={102}><Ok>Auto-fixed 3 issue(s)</Ok></TermLine>
            <TermLine startFrame={110}><Ok>All checks passed!</Ok></TermLine>
          </Terminal>

          <Badge text="One command fixes gitignore, hooks, and team onboarding" startFrame={125} />
        </AbsoluteFill>
      </Sequence>

      {/* === Scene 8: CTA (1140-1350, 7s) === */}
      <Sequence from={1140} durationInFrames={210}>
        <AbsoluteFill style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", zIndex: 1 }}>
          <div style={{ ...useSlideUp(5, 15), fontSize: "48px", fontWeight: 900, letterSpacing: "-0.05em", textAlign: "center" }}>
            Delegate everything to AI.
          </div>
          <div style={{ ...useSlideUp(12, 15), fontSize: "48px", fontWeight: 900, letterSpacing: "-0.05em", color: BLUE_B, textAlign: "center" }}>
            Keep your keys safe.
          </div>

          <div style={{
            ...useSlideUp(28, 15), marginTop: "36px",
            display: "flex", gap: "16px", fontFamily: mono, fontSize: "14px",
          }}>
            {["init", "wrap", "watch", "doctor --fix"].map((cmd, i) => (
              <div key={cmd} style={{
                ...useSlideUp(30 + i * 4, 10),
                padding: "8px 16px", background: S1,
                border: `1px solid ${BORDER}`, borderRadius: "8px", color: BLUE_B,
              }}>
                phantom {cmd}
              </div>
            ))}
          </div>

          <div style={{ ...useSlideUp(55, 12), marginTop: "32px", fontSize: "18px", color: T2 }}>
            Open source. Written in Rust. MIT licensed.
          </div>
          <div style={{ ...useSlideUp(65, 12), marginTop: "20px", padding: "14px 32px", background: BLUE, color: "#fff", borderRadius: "8px", fontSize: "18px", fontWeight: 600 }}>
            phm.dev
          </div>
          <div style={{ ...useSlideUp(75, 12), marginTop: "12px", fontSize: "14px", color: T3 }}>
            @masonwyatt23
          </div>
        </AbsoluteFill>
      </Sequence>
    </AbsoluteFill>
  );
};
