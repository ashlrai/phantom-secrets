"use client";

import { useEffect } from "react";

function CopyButton({ text }: { text: string }) {
  return (
    <div
      className="inst-cmd"
      onClick={() => {
        navigator.clipboard.writeText(text);
        const t = document.getElementById("toast");
        if (t) {
          t.classList.add("show");
          setTimeout(() => t.classList.remove("show"), 1800);
        }
      }}
    >
      $ {text}
    </div>
  );
}

export default function Home() {
  useEffect(() => {
    // Scroll reveal
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((x) => {
          if (x.isIntersecting) {
            x.target.classList.add("v");
            io.unobserve(x.target);
          }
        });
      },
      { threshold: 0.08, rootMargin: "0px 0px -40px 0px" }
    );
    document.querySelectorAll(".sr").forEach((el) => io.observe(el));

    // Terminal demo
    const demoEl = document.getElementById("demo-term");
    if (demoEl) {
      const dObs = new IntersectionObserver(
        (entries) => {
          entries.forEach((x) => {
            if (x.isIntersecting) {
              typeTerminal("demo-body");
              dObs.disconnect();
            }
          });
        },
        { threshold: 0.15 }
      );
      dObs.observe(demoEl);
    }

    return () => io.disconnect();
  }, []);

  return (
    <>
      <style>{`
        :root{
          --bg:#050508;--s1:#0a0a12;--s2:#101018;
          --border:#1a1a2c;--border-l:#252538;
          --t1:#f5f5f7;--t2:#a1a1b5;--t3:#65657a;
          --blue:#3b82f6;--blue-b:#60a5fa;--blue-d:#1d4ed8;
          --green:#22c55e;--red:#ef4444;
        }
        ::selection{background:rgba(59,130,246,.3)}
        code{font-family:'SF Mono','Fira Code','Cascadia Code',monospace}

        nav{position:fixed;top:0;left:0;right:0;z-index:100;background:rgba(5,5,8,.82);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);border-bottom:1px solid rgba(26,26,44,.5)}
        nav .w{display:flex;align-items:center;justify-content:space-between;height:56px}
        .n-logo{display:flex;align-items:center;gap:9px;text-decoration:none;color:var(--t1)}
        .n-logo img{width:22px;height:22px}
        .n-logo span{font-weight:700;font-size:.95rem;letter-spacing:-.02em}
        .n-r{display:flex;gap:20px;align-items:center}
        .n-r a{color:var(--t2);text-decoration:none;font-size:.85rem;font-weight:500;transition:color .15s}
        .n-r a:hover{color:var(--t1)}
        .n-gh{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--s2);border:1px solid var(--border);border-radius:6px;font-size:.82rem;font-weight:600;color:var(--t1)!important;transition:border-color .2s}
        .n-gh:hover{border-color:var(--blue)}

        .w{max-width:1060px;margin:0 auto;padding:0 28px}
        .hero{padding:130px 0 60px;text-align:center;position:relative;overflow:hidden}
        .hero::before{content:'';position:absolute;top:-200px;left:50%;width:1200px;height:900px;transform:translateX(-50%);background:radial-gradient(ellipse at 50% 35%,rgba(59,130,246,.06) 0%,transparent 60%);pointer-events:none}
        .hero h1{font-size:clamp(3rem,7.5vw,5.2rem);font-weight:900;letter-spacing:-.06em;line-height:1;margin-bottom:20px;color:#fff}
        .hero h1 em{font-style:normal;color:var(--blue-b);display:block}
        .hero-sub{font-size:1.05rem;color:var(--t2);max-width:480px;margin:0 auto 32px;line-height:1.75}
        .hero-btns{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-bottom:56px}
        .btn{display:inline-flex;align-items:center;gap:8px;padding:12px 24px;border-radius:8px;font-size:.9rem;font-weight:600;text-decoration:none;transition:all .2s;border:1px solid transparent;letter-spacing:-.01em}
        .btn-p{background:var(--blue);color:#fff;border-color:var(--blue)}
        .btn-p:hover{background:var(--blue-d);transform:translateY(-1px);box-shadow:0 4px 24px rgba(59,130,246,.3)}
        .btn-s{background:transparent;color:var(--t1);border-color:var(--border-l)}
        .btn-s:hover{border-color:var(--t3)}

        .flow{max-width:860px;margin:0 auto;position:relative}
        .flow-row{display:grid;grid-template-columns:1fr auto 1fr auto 1fr;gap:0;align-items:center}
        .flow-node{background:var(--s1);border:1px solid var(--border);border-radius:14px;padding:24px 20px;text-align:left}
        .flow-node.center{border-color:var(--blue-d);box-shadow:0 0 40px rgba(59,130,246,.1),0 0 0 1px rgba(59,130,246,.15) inset}
        .flow-label{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--t3);margin-bottom:10px}
        .flow-node.center .flow-label{color:var(--blue-b)}
        .flow-code{font-family:'SF Mono','Fira Code',monospace;font-size:.75rem;line-height:1.9}
        .flow-code .k{color:var(--t3)}.flow-code .vb{color:var(--blue-b)}.flow-code .vg{color:var(--green)}
        .flow-conn{display:flex;flex-direction:column;align-items:center;gap:4px;padding:0 8px}
        .flow-arrow{width:48px;height:2px;background:linear-gradient(90deg,var(--border),var(--blue),var(--border));position:relative;border-radius:1px}
        .flow-arrow::after{content:'';position:absolute;right:-1px;top:-3px;border:4px solid transparent;border-left:6px solid var(--blue)}
        .flow-dot{width:6px;height:6px;border-radius:50%;background:var(--blue);animation:pulse-dot 2s ease-in-out infinite}
        .flow-conn:nth-child(4) .flow-dot{animation-delay:.5s}
        @keyframes pulse-dot{0%,100%{opacity:.3;transform:scale(.8)}50%{opacity:1;transform:scale(1.2)}}
        .flow-tag{font-size:.65rem;color:var(--t3);white-space:nowrap;margin-top:2px}
        .flow-tag span{color:var(--blue-b);font-weight:600}
        .flow-caption{text-align:center;margin-top:20px;font-size:.82rem;color:var(--t3)}
        .flow-caption strong{color:var(--green);font-weight:600}

        section{padding:100px 0}
        .sec-b{border-top:1px solid var(--border)}
        .sec-h{text-align:center;margin-bottom:56px}
        .sec-h h2{font-size:2.2rem;font-weight:800;letter-spacing:-.04em;margin-bottom:12px;color:#fff}
        .sec-h p{color:var(--t2);font-size:1rem;max-width:480px;margin:0 auto;line-height:1.7}

        .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:12px;overflow:hidden}
        .stat{background:var(--s1);padding:40px 24px;text-align:center}
        .stat-n{font-size:3.2rem;font-weight:900;letter-spacing:-.04em;color:#fff}
        .stat-l{color:var(--t2);font-size:.85rem;margin-top:4px}

        .how-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
        .how-card{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:32px;transition:border-color .2s}
        .how-card:hover{border-color:var(--border-l)}
        .how-n{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:7px;background:var(--blue-d);color:#fff;font-weight:700;font-size:.8rem;margin-bottom:16px}
        .how-card h3{font-size:1rem;font-weight:700;margin-bottom:6px}
        .how-card p{color:var(--t2);font-size:.88rem;line-height:1.6}
        .how-card code{background:var(--s2);padding:1px 6px;border-radius:4px;font-size:.78rem;color:var(--blue-b)}

        .term{background:var(--s1);border:1px solid var(--border);border-radius:14px;overflow:hidden;box-shadow:0 32px 80px rgba(0,0,0,.5),0 0 0 1px rgba(255,255,255,.03) inset}
        .term-bar{display:flex;align-items:center;gap:6px;padding:14px 18px;border-bottom:1px solid var(--border)}
        .td{width:10px;height:10px;border-radius:50%;opacity:.45}
        .td-r{background:#ef4444}.td-y{background:#eab308}.td-g{background:#22c55e}
        .term-t{margin-left:auto;font-size:.72rem;color:var(--t3);font-family:monospace}
        .term-body{padding:20px;font-family:'SF Mono','Fira Code',monospace;font-size:.82rem;line-height:2;min-height:100px}
        .term-body .line{display:block;opacity:0;transform:translateY(4px);transition:opacity .25s,transform .25s}
        .term-body .line.vis{opacity:1;transform:none}
        .tp{color:var(--t3)}.tc{color:var(--t1)}.to{color:var(--green);font-weight:600}.ti{color:var(--blue-b)}.td2{color:var(--t2)}
        .cursor-blink{display:inline-block;width:8px;height:16px;background:var(--blue);vertical-align:text-bottom;animation:blink 1s step-end infinite;border-radius:1px}
        @keyframes blink{50%{opacity:0}}

        .feat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
        .feat{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:28px;transition:border-color .2s,transform .2s}
        .feat:hover{border-color:var(--blue-d);transform:translateY(-2px)}
        .feat h3{font-size:.92rem;font-weight:700;margin-bottom:6px}
        .feat p{color:var(--t2);font-size:.82rem;line-height:1.55}

        .inst-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
        .inst{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:28px}
        .inst h3{font-size:.78rem;color:var(--blue-b);text-transform:uppercase;letter-spacing:.05em;margin-bottom:14px;font-weight:700}
        .inst-cmd{background:var(--s2);border:1px solid var(--border);border-radius:7px;padding:12px 14px;font-family:'SF Mono',monospace;font-size:.8rem;color:var(--t1);cursor:pointer;transition:border-color .15s;line-height:1.6;overflow-x:auto;word-break:break-all}
        .inst-cmd:hover{border-color:var(--blue)}
        .how-grid-3{grid-template-columns:1fr 1fr 1fr}
        html,body{overflow-x:hidden}
        .inst-sub{font-size:.75rem;color:var(--t3);margin-top:10px;text-align:center}

        .cta{text-align:center;position:relative}
        .cta::before{content:'';position:absolute;bottom:-100px;left:50%;width:800px;height:500px;transform:translateX(-50%);background:radial-gradient(50% 50%,rgba(59,130,246,.04) 0%,transparent 100%);pointer-events:none}
        .cta h2{font-size:2.6rem;font-weight:900;letter-spacing:-.04em;margin-bottom:14px;color:#fff}
        .cta p{color:var(--t2);margin-bottom:36px;font-size:1rem}

        footer{padding:32px 0;text-align:center;border-top:1px solid var(--border);color:var(--t3);font-size:.8rem}
        footer a{color:var(--t2);text-decoration:none;transition:color .15s}
        footer a:hover{color:var(--blue-b)}

        .toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(60px);background:var(--blue);color:#fff;padding:8px 20px;border-radius:8px;font-size:.85rem;font-weight:600;opacity:0;transition:all .3s;pointer-events:none;z-index:200}
        .toast.show{opacity:1;transform:translateX(-50%) translateY(0)}

        .sr{opacity:0;transform:translateY(24px);transition:opacity .7s cubic-bezier(.16,1,.3,1),transform .7s cubic-bezier(.16,1,.3,1)}
        .sr.v{opacity:1;transform:none}
        .sr-d1{transition-delay:.08s}.sr-d2{transition-delay:.16s}.sr-d3{transition-delay:.24s}

        @media(max-width:768px){
          .hero h1{font-size:2.4rem}
          .hero-sub{font-size:.92rem}
          .hero{padding:100px 0 40px}
          .hero-installs{flex-direction:column;align-items:stretch}
          .flow-row{grid-template-columns:1fr;gap:12px}
          .flow-conn{flex-direction:row;padding:4px 0;justify-content:center}
          .flow-arrow{width:2px;height:32px;background:linear-gradient(180deg,var(--border),var(--blue),var(--border))}
          .flow-arrow::after{right:auto;bottom:-1px;top:auto;left:-3px;border:4px solid transparent;border-top:6px solid var(--blue);border-left:4px solid transparent}
          .flow-code{font-size:.65rem}
          .flow-node{padding:16px 14px}
          .stats,.how-grid,.how-grid-3,.feat-grid,.inst-grid{grid-template-columns:1fr}
          .n-r a:not(.n-gh){display:none}
          section{padding:60px 0}
          .sec-h h2{font-size:1.6rem}
          .sec-h p{font-size:.88rem}
          .stat-n{font-size:2.2rem}
          .stat{padding:28px 16px}
          .cta h2{font-size:1.8rem}
          .inst-cmd{font-size:.7rem;padding:10px 12px}
          .feat{padding:20px}
          .feat-grid{gap:10px}
          .how-card{padding:20px}
          .btn{padding:10px 18px;font-size:.84rem}
          .hero-btns{margin-bottom:32px}
          .w{padding:0 16px}
        }
      `}</style>

      {/* NAV */}
      <nav>
        <div className="w">
          <a href="/" className="n-logo">
            <img src="/favicon.svg" alt="Phantom" />
            <span>Phantom</span>
          </a>
          <div className="n-r">
            <a href="#how">How it works</a>
            <a href="#features">Features</a>
            <a href="/pricing">Pricing</a>
            <a href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md">Docs</a>
            <a
              href="https://github.com/ashlrai/phantom-secrets"
              className="n-gh"
            >
              <svg width="15" height="15" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
              </svg>
              GitHub
            </a>
          </div>
        </div>
      </nav>

      <div className="w">
        {/* HERO */}
        <header className="hero">
          <h1 className="sr">
            AI uses your keys.<em>Safely.</em>
          </h1>
          <p className="sr sr-d1 hero-sub">
            Tell Claude to integrate Stripe. Let Cursor build your OpenAI
            pipeline. Phantom lets AI use your real API keys to do real work
            &mdash; without the keys ever being exposed.
          </p>
          <div className="sr sr-d2 hero-btns">
            <a href="https://github.com/ashlrai/phantom-secrets" className="btn btn-p">
              Get started &mdash; it&apos;s free
            </a>
            <a href="#how" className="btn btn-s">How it works</a>
          </div>
          <div className="sr sr-d3" style={{ marginBottom: 40 }}>
            <div className="hero-installs" style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
              <div style={{ textAlign: "left" }}>
                <div style={{ fontSize: ".7rem", color: "var(--t3)", marginBottom: 4, fontWeight: 600, textTransform: "uppercase", letterSpacing: ".05em" }}>CLI</div>
                <CopyButton text="npx phantom-secrets init" />
              </div>
              <div style={{ textAlign: "left" }}>
                <div style={{ fontSize: ".7rem", color: "var(--blue-b)", marginBottom: 4, fontWeight: 600, textTransform: "uppercase", letterSpacing: ".05em" }}>Claude Code</div>
                <CopyButton text="claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp" />
              </div>
            </div>
            <div style={{ fontSize: ".78rem", color: "var(--t3)", marginTop: 8 }}>
              One command to protect your .env. One command for Claude Code MCP.
            </div>
          </div>

          {/* FLOW DIAGRAM */}
          <div className="sr sr-d3 flow">
            <div className="flow-row">
              <div className="flow-node">
                <div className="flow-label">Your .env file</div>
                <div className="flow-code">
                  <span className="k">OPENAI_API_KEY=</span><span className="vb">phm_d9f1c1...</span><br />
                  <span className="k">STRIPE_SECRET=</span><span className="vb">phm_2ccb5a...</span><br />
                  <span className="k">DATABASE_URL=</span><span className="vb">phm_99a8d2...</span>
                </div>
              </div>
              <div className="flow-conn">
                <div className="flow-dot"></div>
                <div className="flow-arrow"></div>
                <div className="flow-tag">AI sees: <span>phm_</span> tokens</div>
              </div>
              <div className="flow-node center">
                <div className="flow-label">Phantom Proxy</div>
                <div className="flow-code">
                  <span className="vb">phm_d9f1c1...</span> <span className="k">&rarr;</span> <span className="vg">sk-proj-real...</span><br />
                  <span className="vb">phm_2ccb5a...</span> <span className="k">&rarr;</span> <span className="vg">sk_live-real...</span><br />
                  <span className="vb">phm_99a8d2...</span> <span className="k">&rarr;</span> <span className="vg">postgres://...</span>
                </div>
              </div>
              <div className="flow-conn">
                <div className="flow-dot"></div>
                <div className="flow-arrow"></div>
                <div className="flow-tag">API gets: <span>real keys</span></div>
              </div>
              <div className="flow-node">
                <div className="flow-label">Upstream APIs</div>
                <div className="flow-code">
                  <span className="vg">api.openai.com</span> <span className="k">&#10003;</span><br />
                  <span className="vg">api.stripe.com</span> <span className="k">&#10003;</span><br />
                  <span className="vg">db.example.com</span> <span className="k">&#10003;</span>
                </div>
              </div>
            </div>
            <div className="flow-caption">
              <strong>&#10003;</strong> Real keys never enter the AI context window. Injected at network layer only.
            </div>
          </div>
        </header>

        {/* GET STARTED */}
        <section className="sec-b sr" id="start">
          <div className="sec-h">
            <h2>Get started in 60 seconds</h2>
            <p>Three commands. No config files to write. No accounts to create.</p>
          </div>
          <div className="how-grid how-grid-3">
            <div className="how-card sr" style={{ textAlign: "center" }}>
              <div className="how-n">1</div>
              <h3>Install &amp; protect</h3>
              <CopyButton text="npx phantom-secrets init" />
              <p style={{ color: "var(--t3)", fontSize: ".82rem", marginTop: 8 }}>
                Installs Phantom, reads your .env, stores real secrets in an encrypted vault, rewrites .env with phantom tokens.
              </p>
            </div>
            <div className="how-card sr" style={{ textAlign: "center" }}>
              <div className="how-n">2</div>
              <h3>Configure Claude Code</h3>
              <CopyButton text="phantom setup" />
              <p style={{ color: "var(--t3)", fontSize: ".82rem", marginTop: 8 }}>
                Adds Phantom&apos;s MCP server to Claude Code and allows it to read your .env (which now only has phantom tokens).
              </p>
            </div>
            <div className="how-card sr" style={{ textAlign: "center" }}>
              <div className="how-n">3</div>
              <h3>Code with AI</h3>
              <CopyButton text="phantom exec -- claude" />
              <p style={{ color: "var(--t3)", fontSize: ".82rem", marginTop: 8 }}>
                Starts the proxy, launches Claude Code. AI sees phantom tokens. Real keys injected at the network layer. Done.
              </p>
            </div>
          </div>
        </section>

        {/* STATS */}
        <section className="sec-b sr">
          <div className="sec-h">
            <h2>You know the risk. You take it anyway.</h2>
            <p>You paste API keys into Claude Code. You let Cursor read your .env. You know it&apos;s risky &mdash; but AI doing your work is worth it. Phantom fixes this.</p>
          </div>
          <div className="stats">
            <div className="stat"><div className="stat-n">39.6M</div><div className="stat-l">secrets leaked on GitHub in 2025</div></div>
            <div className="stat"><div className="stat-n">2&times;</div><div className="stat-l">higher leak rate with AI-assisted commits</div></div>
            <div className="stat"><div className="stat-n">+81%</div><div className="stat-l">YoY increase in AI service key leaks</div></div>
          </div>
        </section>

        {/* USE CASES */}
        <section className="sr">
          <div className="sec-h">
            <h2>Let AI do real work with your keys</h2>
            <p>Phantom doesn&apos;t restrict AI &mdash; it enables it. Tell Claude or Cursor to use your real APIs. Everything just works.</p>
          </div>
          <div className="how-grid">
            <div className="how-card sr">
              <div className="how-n" style={{ background: "var(--green)" }}>&#10003;</div>
              <h3>&ldquo;Integrate Stripe payments&rdquo;</h3>
              <p>Claude writes the code, tests it against your real Stripe key. The key flows through the proxy &mdash; Claude never sees <code>sk_live_...</code>, but the integration works.</p>
            </div>
            <div className="how-card sr">
              <div className="how-n" style={{ background: "var(--green)" }}>&#10003;</div>
              <h3>&ldquo;Build an OpenAI chatbot&rdquo;</h3>
              <p>Cursor reads your .env, sees <code>phm_d9f1...</code>. It writes code that calls OpenAI. The proxy injects your real key. The chatbot works. The key stays safe.</p>
            </div>
            <div className="how-card sr">
              <div className="how-n" style={{ background: "var(--green)" }}>&#10003;</div>
              <h3>&ldquo;Deploy to Vercel&rdquo;</h3>
              <p>Run <code>phantom sync --platform vercel</code> to push real secrets to your deployment. No more copying keys into dashboards. One command, all environments.</p>
            </div>
            <div className="how-card sr">
              <div className="how-n" style={{ background: "var(--green)" }}>&#10003;</div>
              <h3>&ldquo;Set up this project on my new laptop&rdquo;</h3>
              <p>Run <code>phantom pull --from vercel</code> to import all secrets. Your vault syncs. No Slack messages asking for the .env file.</p>
            </div>
          </div>
        </section>

        {/* HOW IT WORKS */}
        <section className="sec-b sr" id="how">
          <div className="sec-h">
            <h2>Two commands. No code changes.</h2>
            <p>Works underneath your existing workflow. Nothing to learn.</p>
          </div>
          <div className="how-grid">
            <div className="how-card sr"><div className="how-n">1</div><h3>Protect your secrets</h3><p>Run <code>phantom init</code>. Real secrets move to an encrypted vault. Your <code>.env</code> is rewritten with worthless <code>phm_</code> tokens. Auto-detects 13+ services.</p></div>
            <div className="how-card sr"><div className="how-n">2</div><h3>Code with AI</h3><p>Run <code>phantom exec -- claude</code>. A local proxy starts. AI reads your .env, sees only phantom tokens. Fresh tokens every session.</p></div>
            <div className="how-card sr"><div className="how-n">3</div><h3>Everything just works</h3><p>When code calls an API, the proxy swaps the phantom token for your real credential and forwards over TLS. Your code works perfectly. AI never knew.</p></div>
            <div className="how-card sr"><div className="how-n">4</div><h3>Sync everywhere</h3><p><code>phantom sync</code> pushes secrets to Vercel and Railway. <code>phantom pull</code> imports them on a new machine. One source of truth.</p></div>
          </div>
        </section>

        {/* TERMINAL DEMO */}
        <section className="sec-b sr">
          <div className="sec-h">
            <h2>See it in action</h2>
            <p>The full workflow from protecting secrets to deploying them.</p>
          </div>
          <div className="term" id="demo-term">
            <div className="term-bar">
              <span className="td td-r"></span>
              <span className="td td-y"></span>
              <span className="td td-g"></span>
              <span className="term-t">~/my-app</span>
            </div>
            <div className="term-body" id="demo-body"></div>
          </div>
        </section>

        {/* FEATURES */}
        <section className="sr" id="features">
          <div className="sec-h">
            <h2>Security + developer experience</h2>
            <p>Not just safer &mdash; faster. One tool for local dev, AI coding, and deployment.</p>
          </div>
          <div className="feat-grid">
            <div className="feat sr"><h3>Encrypted vault</h3><p>ChaCha20-Poly1305 with Argon2id. OS keychain on macOS/Linux. Encrypted file fallback for CI and Docker.</p></div>
            <div className="feat sr"><h3>Session tokens</h3><p>Fresh phantom tokens every session. If one leaks from AI logs or context, it&apos;s already invalid.</p></div>
            <div className="feat sr"><h3>MCP server</h3><p>Native Claude Code integration. AI manages secrets through MCP tools without ever seeing real values.</p></div>
            <div className="feat sr"><h3>Pre-commit hook</h3><p><code>phantom check</code> blocks commits containing unprotected secrets. Catches hardcoded keys before they ship.</p></div>
            <div className="feat sr"><h3>Platform sync</h3><p>Push secrets to Vercel and Railway. Pull to onboard new machines. No more copying keys through Slack.</p></div>
            <div className="feat sr"><h3>Smart detection</h3><p>Auto-detects 13+ services from key names. Knows <code>OPENAI_API_KEY</code> from <code>NODE_ENV</code>.</p></div>
            <div className="feat sr"><h3>Streaming proxy</h3><p>Full SSE/streaming support. OpenAI and Anthropic streaming responses work perfectly through the proxy.</p></div>
            <div className="feat sr"><h3>Open source</h3><p>MIT licensed. Written in Rust. 56+ tests. Auditable, forkable, free forever.</p></div>
            <div className="feat sr"><h3>Cloud sync</h3><p><code>phantom cloud push</code> backs up your vault to Phantom Cloud. Sync secrets across machines. End-to-end encrypted.</p></div>
          </div>
        </section>

        {/* INSTALL */}
        <section className="sec-b sr">
          <div className="sec-h"><h2>Install in 10 seconds</h2></div>
          <div className="inst-grid">
            <div className="inst">
              <h3>npm</h3>
              <CopyButton text="npx phantom-secrets init" />
              <div className="inst-sub">Downloads binary automatically</div>
            </div>
            <div className="inst">
              <h3>Homebrew</h3>
              <CopyButton text="brew tap ashlrai/phantom && brew install phantom" />
              <div className="inst-sub">macOS</div>
            </div>
            <div className="inst">
              <h3>Cargo</h3>
              <CopyButton text="cargo install phantom --git https://github.com/ashlrai/phantom-secrets" />
              <div className="inst-sub">Build from source</div>
            </div>
            <div className="inst" style={{ borderColor: "var(--blue-d)" }}>
              <h3>Claude Code</h3>
              <CopyButton text="claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp" />
              <div className="inst-sub">One command, Claude handles the rest</div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="cta sr">
          <h2>Let AI do the work.<br />Keep your keys safe.</h2>
          <p>Two commands. Two minutes. Full AI delegation without the security risk.</p>
          <div className="hero-btns">
            <a href="https://github.com/ashlrai/phantom-secrets" className="btn btn-p">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
              </svg>
              View on GitHub
            </a>
            <a href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md" className="btn btn-s">
              Read the docs
            </a>
          </div>
        </section>
      </div>

      <footer>
        <p>
          Built by <a href="https://ashlar.ai">Ashlar AI</a> &middot;{" "}
          <a href="https://github.com/ashlrai/phantom-secrets">GitHub</a> &middot;{" "}
          <a href="https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md">Docs</a> &middot;{" "}
          <a href="/pricing">Pricing</a> &middot; MIT License
        </p>
      </footer>

      <div className="toast" id="toast">Copied to clipboard</div>
    </>
  );
}

function typeTerminal(id: string) {
  const el = document.getElementById(id);
  if (!el || el.dataset.done) return;
  el.dataset.done = "1";
  el.innerHTML = "";
  const container = el;

  const lines = [
    { cmd: "phantom sync --platform vercel" },
    { out: '<span class="ti">-></span> <span class="td2">Syncing 3 secret(s) to</span> <span class="ti">vercel</span><span class="td2">...</span>' },
    { out: '<span class="td2">   </span><span class="to">+</span> <span class="tc">OPENAI_API_KEY</span> <span class="td2">(created)</span>', d: 50 },
    { out: '<span class="td2">   </span><span class="to">+</span> <span class="tc">STRIPE_SECRET</span> <span class="td2">(created)</span>', d: 50 },
    { out: '<span class="td2">   </span><span class="to">~</span> <span class="tc">DATABASE_URL</span> <span class="td2">(updated)</span>', d: 50 },
    { out: '<span class="to">ok</span> <span class="td2">vercel: 2 created, 1 updated</span>', d: 300 },
    { cmd: "phantom cloud push" },
    { out: '<span class="ti">-></span> <span class="td2">Encrypting 3 secret(s) client-side...</span>' },
    { out: '<span class="to">ok</span> <span class="td2">3 secret(s) synced to cloud (v1)</span><span class="cursor-blink"></span>' },
  ];

  let i = 0;
  function next() {
    if (i >= lines.length) return;
    const ln = lines[i] as { cmd?: string; out?: string; d?: number };
    const s = document.createElement("span");
    s.className = "line";
    container.appendChild(s);
    requestAnimationFrame(() => s.classList.add("vis"));

    if (ln.cmd) {
      const pr = document.createElement("span");
      pr.className = "tp";
      pr.textContent = "$ ";
      s.appendChild(pr);
      let c = 0;
      const iv = setInterval(() => {
        if (c < ln.cmd!.length) {
          const ch = document.createElement("span");
          ch.className = "tc";
          ch.textContent = ln.cmd![c];
          s.appendChild(ch);
          c++;
        } else {
          clearInterval(iv);
          s.appendChild(document.createElement("br"));
          i++;
          setTimeout(next, 200);
        }
      }, 25);
    } else {
      s.innerHTML = ln.out + "<br>";
      i++;
      setTimeout(next, ln.d || 60);
    }
  }
  next();
}
