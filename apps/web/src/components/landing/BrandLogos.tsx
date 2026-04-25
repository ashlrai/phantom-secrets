// Real brand SVG marks rendered in their actual brand colors.
// Multi-color brands (Gemini, Slack, Figma, GCP, Cloudflare) are
// reproduced with proper multi-fill paths or gradients.
// Single-color brands use the brand's primary identity color.
//
// All SVGs are 24×24 viewBox. Pass `className` to size them.

import type { SVGProps } from "react";

type LogoProps = SVGProps<SVGSVGElement>;

/* ── Multi-color brands ──────────────────────────────────────── */

export function GeminiLogo(props: LogoProps) {
  // Gemini's official 4-pointed-star mark with the canonical Google
  // Gemini gradient: Google blue → violet → coral. Diagonal top-left
  // to bottom-right, matching gemini.google.com.
  return (
    <svg viewBox="0 0 24 24" aria-label="Gemini" {...props}>
      <defs>
        <linearGradient id="gemini-grad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#1c7bd7" />
          <stop offset="35%" stopColor="#4285f4" />
          <stop offset="65%" stopColor="#9168c0" />
          <stop offset="100%" stopColor="#d96570" />
        </linearGradient>
      </defs>
      <path
        d="M12 24A14.304 14.304 0 0 0 0 12 14.304 14.304 0 0 0 12 0a14.304 14.304 0 0 0 12 12 14.304 14.304 0 0 0-12 12Z"
        fill="url(#gemini-grad)"
      />
    </svg>
  );
}

export function SlackLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" {...props}>
      {/* Top-left magenta */}
      <path
        d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313z"
        fill="#e01e5a"
      />
      {/* Top-right green */}
      <path
        d="M8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312z"
        fill="#36c5f0"
      />
      {/* Bottom-right yellow */}
      <path
        d="M18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312z"
        fill="#2eb67d"
      />
      {/* Bottom-left blue */}
      <path
        d="M15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"
        fill="#ecb22e"
      />
    </svg>
  );
}

export function FigmaLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" {...props}>
      {/* Top-left red */}
      <path
        d="M8.148 0H12.736v8.981H8.148C5.672 8.981 3.658 6.967 3.658 4.491S5.672 0 8.148 0z"
        fill="#f24e1e"
      />
      {/* Top-right orange */}
      <path
        d="M12.736 0h4.588c2.476 0 4.49 2.014 4.49 4.49S19.812 8.981 17.336 8.981H12.736V0z"
        fill="#ff7262"
      />
      {/* Middle-right purple (circle) */}
      <path
        d="M22.342 13.49c0 2.476-2.013 4.49-4.488 4.49S13.366 15.967 13.366 13.49 15.379 9 17.854 9s4.488 2.013 4.488 4.49z"
        fill="#a259ff"
      />
      {/* Middle-left blue */}
      <path
        d="M3.658 13.49c0-2.475 2.014-4.49 4.49-4.49h4.588v8.981H8.148c-2.476 0-4.49-2.013-4.49-4.49z"
        fill="#1abcfe"
      />
      {/* Bottom-left green */}
      <path
        d="M3.658 22.49c0-2.476 2.014-4.49 4.49-4.49h4.588v4.49c0 2.476-2.014 4.49-4.49 4.49S3.658 24.967 3.658 22.49z"
        fill="#0acf83"
        transform="translate(0,-2.51)"
      />
    </svg>
  );
}

export function GcpLogo(props: LogoProps) {
  // Google Cloud — the actual cloud silhouette with the four Google
  // brand colors arranged as a continuous outline (each quadrant of
  // the cloud picks up one color, matching Google's official mark).
  return (
    <svg viewBox="0 0 24 24" aria-label="Google Cloud" {...props}>
      <defs>
        <linearGradient id="gcp-grad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#4285f4" />
          <stop offset="33%" stopColor="#34a853" />
          <stop offset="66%" stopColor="#fbbc04" />
          <stop offset="100%" stopColor="#ea4335" />
        </linearGradient>
      </defs>
      {/* Cloud silhouette */}
      <path
        d="M17 9.5h-.4A6 6 0 0 0 5.7 11a4.5 4.5 0 0 0 .8 8.95h10.5a5.25 5.25 0 0 0 .5-10.45z"
        fill="url(#gcp-grad)"
      />
      {/* Letter G centered, cut out of the cloud */}
      <path
        d="M11.5 13.5h2v1.2h-1.1c.05.3-.05.6-.3.85a1.4 1.4 0 0 1-1 .35 1.7 1.7 0 0 1-1.7-1.7 1.7 1.7 0 0 1 1.7-1.7c.45 0 .85.16 1.15.42l.7-.7a2.65 2.65 0 0 0-1.85-.72 2.7 2.7 0 0 0 0 5.4 2.4 2.4 0 0 0 1.85-.75 2.5 2.5 0 0 0 .65-1.8c0-.18-.02-.35-.04-.52z"
        fill="#ffffff"
      />
    </svg>
  );
}

export function CloudflareLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" {...props}>
      <defs>
        <linearGradient id="cf-grad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#fbad41" />
          <stop offset="100%" stopColor="#f48120" />
        </linearGradient>
      </defs>
      <path
        d="M16.5088 16.8447l.211-.7319c.2515-.8649.1641-1.6667-.246-2.2585-.378-.5407-1.0078-.8624-1.7715-.9013l-14.4339-.1828a.286.286 0 01-.2275-.1207.2922.2922 0 01-.0328-.2575.3832.3832 0 01.3372-.2533l14.5663-.1828c1.7281-.0793 3.5993-1.4798 4.2535-3.1936l.8328-2.1758a.5089.5089 0 00.0234-.2902C19.9818 3.0828 16.6586 0 12.6043 0c-3.7295 0-6.9038 2.604-7.7536 6.105a3.6437 3.6437 0 00-2.55-.7081C.5417 5.5715-.0697 7.0312.0066 8.382l.0086.124a.2902.2902 0 01-.2585.3158l-.082.0157c-.4108.0772-.8016.2274-1.1632.4456l-.5142.2871c-.5184.2934-.8893.7577-1.0386 1.3218a3.0252 3.0252 0 00.0386 1.6953l.5232 1.5318c.071.2078.2647.3473.4842.3473h22.5538c.0237 0 .0473-.0008.0708-.0028l.0247-.0014a.2879.2879 0 00.2188-.197z"
        fill="url(#cf-grad)"
      />
    </svg>
  );
}

export function AwsLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" {...props}>
      {/* AWS smile arc — orange */}
      <path
        d="M22.43 16.7c-3.05 2.18-7.47 3.34-11.27 3.34-5.33 0-10.13-1.97-13.76-5.25-.28-.26-.03-.6.31-.4 3.92 2.28 8.78 3.66 13.79 3.66 3.38 0 7.1-.7 10.52-2.16.51-.22.94.34.41.81z"
        fill="#ff9900"
      />
      <path
        d="M23.7 15.25c-.39-.5-2.59-.24-3.58-.12-.3.04-.34-.22-.07-.41 1.75-1.23 4.62-.88 4.96-.46.34.42-.09 3.3-1.73 4.67-.25.21-.49.1-.38-.18.37-.92 1.19-2.99.8-3.5z"
        fill="#ff9900"
      />
      {/* Black wordmark approximation */}
      <path
        d="M6.83 9.7c0 .42.05.76.13 1l.42.91c.04.07.06.14.06.2 0 .09-.05.18-.17.27l-.55.37a.4.4 0 0 1-.23.08c-.09 0-.17-.04-.26-.13a2.66 2.66 0 0 1-.31-.41 6.85 6.85 0 0 1-.27-.51c-.68.8-1.54 1.21-2.57 1.21-.74 0-1.32-.21-1.74-.63a2.32 2.32 0 0 1-.65-1.68c0-.74.26-1.34.79-1.79a3.13 3.13 0 0 1 2.13-.68c.3 0 .61.03.93.07.34.05.68.11 1.03.19v-.64c0-.66-.14-1.13-.41-1.4-.28-.27-.75-.4-1.43-.4-.31 0-.62.04-.95.11-.32.08-.64.18-.94.3a2.5 2.5 0 0 1-.31.11c-.05.01-.1.02-.13.02-.12 0-.18-.09-.18-.27v-.43c0-.14.02-.24.06-.31a.65.65 0 0 1 .25-.18c.31-.16.67-.29 1.1-.4a5.3 5.3 0 0 1 1.36-.16c1.04 0 1.79.24 2.27.71.48.47.72 1.18.72 2.14V9.7z"
        fill="#ffffff"
      />
    </svg>
  );
}

/* ── Single brand-color logos ────────────────────────────────── */

export function ClaudeLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#cc785c" aria-label="Claude" {...props}>
      <path d="M4.709 15.955l4.72-2.647.079-.23-.079-.128H9.2l-.79-.048-2.698-.073-2.339-.097-2.266-.122-.571-.121L0 11.784l.055-.352.48-.321.686.06 1.52.103 2.278.158 1.652.097 2.449.255h.389l.055-.157-.134-.098-.103-.097-2.358-1.596-2.552-1.688-1.336-.972-.724-.491-.364-.462-.158-1.008.656-.722.881.06.225.061.893.686 1.908 1.476 2.491 1.833.365.304.146-.103.018-.073-.164-.274-1.355-2.446-1.446-2.49-.644-1.032-.17-.619a2.97 2.97 0 01-.104-.729L6.283.134 6.696 0l.996.134.42.364.62 1.414 1.002 2.229 1.555 3.03.456.898.243.832.091.255h.158V9.01l.128-1.706.237-2.095.23-2.695.08-.76.376-.91.747-.492.584.28.48.685-.067.444-.286 1.851-.559 2.903-.364 1.942h.212l.243-.243.985-1.306 1.652-2.064.73-.82.85-.904.547-.431h1.033l.76 1.129-.34 1.166-1.064 1.347-.881 1.142-1.264 1.7-.79 1.36.073.11.188-.02 2.856-.606 1.543-.28 1.841-.315.833.388.091.395-.328.807-1.969.486-2.309.462-3.439.813-.042.03.049.061 1.549.146.662.036h1.622l3.02.225.79.522.474.638-.079.485-1.215.62-1.64-.389-3.829-.91-1.312-.329h-.182v.11l1.093 1.068 2.006 1.81 2.509 2.33.127.578-.322.455-.34-.049-2.205-1.657-.851-.747-1.926-1.62h-.128v.17l.444.649 2.345 3.521.122 1.08-.17.353-.608.213-.668-.122-1.374-1.925-1.415-2.167-1.143-1.943-.14.08-.674 7.254-.316.37-.729.28-.607-.461-.322-.747.322-1.476.389-1.924.315-1.53.286-1.9.17-.632-.012-.042-.14.018-1.434 1.967-2.18 2.945-1.726 1.845-.414.164-.717-.37.067-.662.401-.589 2.388-3.036 1.44-1.882.93-1.087-.006-.158h-.055L4.132 18.56l-1.13.146-.487-.456.061-.746.231-.243 1.908-1.312z" />
    </svg>
  );
}

export function OpenAILogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#ffffff" aria-label="OpenAI" {...props}>
      <path d="M22.282 9.821a5.985 5.985 0 0 0-.516-4.91 6.046 6.046 0 0 0-6.51-2.9A6.065 6.065 0 0 0 4.981 4.18a5.985 5.985 0 0 0-3.998 2.9 6.046 6.046 0 0 0 .743 7.097 5.98 5.98 0 0 0 .51 4.911 6.051 6.051 0 0 0 6.515 2.9A5.985 5.985 0 0 0 13.26 24a6.056 6.056 0 0 0 5.772-4.206 5.99 5.99 0 0 0 3.997-2.9 6.056 6.056 0 0 0-.747-7.073zM13.26 22.43a4.476 4.476 0 0 1-2.876-1.04l.141-.081 4.779-2.758a.795.795 0 0 0 .392-.681v-6.737l2.02 1.168a.071.071 0 0 1 .038.052v5.583a4.504 4.504 0 0 1-4.494 4.494zM3.6 18.304a4.47 4.47 0 0 1-.535-3.014l.142.085 4.783 2.759a.771.771 0 0 0 .78 0l5.843-3.369v2.332a.08.08 0 0 1-.033.062L9.74 19.95a4.5 4.5 0 0 1-6.14-1.646zM2.34 7.896a4.485 4.485 0 0 1 2.366-1.973V11.6a.766.766 0 0 0 .388.676l5.815 3.355-2.02 1.168a.076.076 0 0 1-.071 0l-4.83-2.786A4.504 4.504 0 0 1 2.34 7.872zm16.597 3.855l-5.833-3.387L15.119 7.2a.076.076 0 0 1 .071 0l4.83 2.791a4.494 4.494 0 0 1-.676 8.105v-5.678a.79.79 0 0 0-.407-.667zm2.01-3.023l-.141-.085-4.774-2.782a.776.776 0 0 0-.785 0L9.409 9.23V6.897a.066.066 0 0 1 .028-.061l4.83-2.787a4.5 4.5 0 0 1 6.68 4.66zm-12.64 4.135l-2.02-1.164a.08.08 0 0 1-.038-.057V6.075a4.5 4.5 0 0 1 7.375-3.453l-.142.08L8.704 5.46a.795.795 0 0 0-.393.681zm1.097-2.365l2.602-1.5 2.607 1.5v2.999l-2.597 1.5-2.607-1.5Z" />
    </svg>
  );
}

export function CursorLogo(props: LogoProps) {
  // Cursor's actual mark — three-faced angular block, viewed from above
  return (
    <svg viewBox="0 0 24 24" aria-label="Cursor" {...props}>
      {/* Right face (lightest) */}
      <path d="M11.925 24l10.425-6-10.425-6L1.5 18l10.425 6z" fill="#ffffff" opacity=".95" />
      {/* Top face (medium) */}
      <path d="M22.35 18V6L11.925 0v12l10.425 6z" fill="#ffffff" opacity=".7" />
      {/* Left face (darkest) */}
      <path d="M11.925 0L1.5 6v12l10.425-6V0z" fill="#ffffff" opacity=".45" />
    </svg>
  );
}

export function VercelLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#ffffff" aria-label="Vercel" {...props}>
      <path d="M24 22.525H0l12-21.05 12 21.05z" />
    </svg>
  );
}

export function StripeLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#635bff" aria-label="Stripe" {...props}>
      <path d="M13.479 9.883c-1.626-.604-2.512-1.067-2.512-1.803 0-.622.511-.977 1.423-.977 1.667 0 3.379.642 4.558 1.22l.666-4.111c-.935-.446-2.847-1.177-5.49-1.177-1.87 0-3.425.489-4.536 1.401-1.155.954-1.757 2.334-1.757 4 0 3.023 1.847 4.312 4.847 5.403 1.936.688 2.579 1.177 2.579 1.934 0 .732-.629 1.155-1.77 1.155-1.469 0-3.866-.719-5.43-1.643l-.674 4.156c1.359.762 3.866 1.535 6.471 1.535 1.96 0 3.601-.467 4.717-1.335 1.246-.973 1.892-2.408 1.892-4.295 0-3.085-1.892-4.382-4.984-5.469Z" />
    </svg>
  );
}

export function GitHubLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#ffffff" aria-label="GitHub" {...props}>
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  );
}

export function SupabaseLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#3ecf8e" aria-label="Supabase" {...props}>
      <path d="M11.9 1.6c-.8 0-1.6.4-2.1 1.1L1.5 13.4c-1.2 1.5-.1 3.7 1.8 3.7h7.4v5.4c0 .8 1 1.2 1.6.5l8.3-10.7c1.2-1.5.1-3.7-1.8-3.7h-7.4V2.8c0-.7-.6-1.2-1.5-1.2z" />
    </svg>
  );
}

export function RailwayLogo(props: LogoProps) {
  // Railway's actual mark — a stylized R-via-rail-tracks: a vertical
  // stem rising from a horizontal track-tile base. Clean, geometric.
  return (
    <svg viewBox="0 0 24 24" fill="#c6c6f5" aria-label="Railway" {...props}>
      {/* Top horizontal bar */}
      <path d="M3 4h18v2H3z" />
      {/* Bottom horizontal bar */}
      <path d="M3 18h18v2H3z" />
      {/* Vertical track ties — six evenly spaced */}
      <path d="M4.5 8h2v8h-2zM8 8h2v8H8zM11.5 8h2v8h-2zM15 8h2v8h-2zM18.5 8h2v8h-2z" />
    </svg>
  );
}

export function PostgresLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#5d8db0" aria-label="PostgreSQL" {...props}>
      <path d="M17.128 0a8.521 8.521 0 0 0-2.218.296l-.041.014a8.668 8.668 0 0 0-1.41-.106c-1.184.02-2.203.305-3.027.792-.81-.275-2.476-.787-4.21-.704-1.072.05-2.246.348-3.106 1.15-.86.803-1.346 2.085-1.222 3.832.037.518.185 1.366.443 2.459.257 1.092.625 2.385 1.087 3.667.461 1.282 1.001 2.554 1.673 3.503.336.475.713.872 1.18 1.158.466.286 1.054.454 1.638.396.41-.04.768-.198 1.077-.4.15.16.31.328.476.483-.215.255-.405.483-.526.673-.273.428-.402.766-.443 1.13-.04.36.02.737.222 1.176.439.953 1.318 1.598 2.34 1.785 1.025.187 2.183-.077 3.13-.792.291.752.875 1.367 1.61 1.682.79.34 1.692.422 2.555.205.864-.218 1.704-.732 2.262-1.515.555-.78.768-1.795.523-2.953a17.43 17.43 0 0 0-.36-1.482c1.046-.156 1.937-.585 2.582-1.245.736-.753 1.117-1.756 1.118-2.954-.001-.358-.045-.737-.139-1.117-.587-2.36-2.063-3.969-3.946-4.748-.94-.39-1.987-.59-3.043-.59-.288 0-.577.014-.864.045-.812-.776-1.722-1.211-2.633-1.49a8.94 8.94 0 0 0-2.62-.379z" />
    </svg>
  );
}

export function DockerLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#2496ed" aria-label="Docker" {...props}>
      <path d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.186m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.185.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.185.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.185.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.184-.186h-2.12a.186.186 0 00-.186.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.185-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288Z" />
    </svg>
  );
}

export function WindsurfLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#19b3a6" aria-label="Windsurf" {...props}>
      <path d="M3 16.5c1.8-2.4 3.6-3.6 6-3.6 2.4 0 3 1.2 4.8 1.2s2.4-1.2 4.2-1.2c1.5 0 2.4.6 3 1.2v3c-.6-.6-1.5-1.2-3-1.2-1.8 0-2.4 1.2-4.2 1.2s-2.4-1.2-4.8-1.2c-2.4 0-4.2 1.2-6 3.6v-3Zm0-6c1.8-2.4 3.6-3.6 6-3.6 2.4 0 3 1.2 4.8 1.2s2.4-1.2 4.2-1.2c1.5 0 2.4.6 3 1.2v3c-.6-.6-1.5-1.2-3-1.2-1.8 0-2.4 1.2-4.2 1.2s-2.4-1.2-4.8-1.2c-2.4 0-4.2 1.2-6 3.6v-3Z" />
    </svg>
  );
}

export function MongoLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#47a248" aria-label="MongoDB" {...props}>
      <path d="M17.193 9.555c-1.264-5.58-4.252-7.414-4.573-8.115-.28-.394-.53-.954-.735-1.44-.036.495-.055.685-.523 1.184-.723.566-4.438 3.682-4.74 10.02-.282 5.912 4.27 9.435 4.888 9.884l.07.05A73.49 73.49 0 0111.91 24h.481c.114-1.032.284-2.056.51-3.07.417-.296.604-.463.85-.693a11.342 11.342 0 003.639-8.464c.01-.814-.103-1.662-.197-2.218zm-5.336 8.195s0-8.291.275-8.29c.213 0 .49 10.695.49 10.695-.381-.045-.765-1.76-.765-2.405z" />
    </svg>
  );
}

export function NotionLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#ffffff" aria-label="Notion" {...props}>
      <path d="M4.459 4.208c.746.606 1.026.56 2.428.466l13.215-.793c.28 0 .047-.28-.046-.326L17.86 1.968c-.42-.326-.981-.7-2.055-.607L3.01 2.295c-.466.046-.56.28-.374.466zm.793 3.08v13.904c0 .747.373 1.027 1.214.98l14.523-.84c.841-.046.935-.56.935-1.167V6.354c0-.606-.233-.933-.748-.887l-15.177.887c-.56.047-.747.327-.747.933zm14.337.745c.093.42 0 .84-.42.888l-.7.14v10.264c-.608.327-1.168.514-1.635.514-.748 0-.935-.234-1.495-.933l-4.577-7.186v6.952L12.21 19s0 .84-1.168.84l-3.222.186c-.093-.186 0-.653.327-.746l.84-.233V9.854L7.822 9.76c-.094-.42.14-1.026.793-1.073l3.456-.233 4.764 7.279v-6.44l-1.215-.139c-.093-.514.28-.887.747-.933zM1.936 1.035l13.31-.98c1.634-.14 2.055-.047 3.082.7l4.249 2.986c.7.513.934.653.934 1.213v16.378c0 1.026-.373 1.634-1.68 1.726l-15.458.934c-.98.047-1.448-.093-1.962-.747l-3.129-4.06c-.56-.747-.793-1.306-.793-1.96V2.667c0-.839.374-1.54 1.447-1.632z" />
    </svg>
  );
}

export function LinearLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#5e6ad2" aria-label="Linear" {...props}>
      <path d="M.403 13.795l9.802 9.802c4.247.768 8.787-.527 12.057-3.798L.403 13.795zM.012 9.872l14.116 14.116c1.124-.083 2.236-.336 3.296-.755L.767 6.576c-.418 1.06-.672 2.172-.755 3.296zm1.785-5.516a12.022 12.022 0 0 0-1.04 1.819L18.83 23.243c.629-.282 1.24-.629 1.819-1.04L1.797 4.356zm2.943-3.205A11.998 11.998 0 0 0 0 11.717L12.282 24a12.001 12.001 0 0 0 7.567-3.151L4.74 1.151z" />
    </svg>
  );
}

export function TwilioLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#f22f46" aria-label="Twilio" {...props}>
      <path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.6 0 12 0zm0 19.7c-4.3 0-7.7-3.5-7.7-7.7 0-4.3 3.5-7.7 7.7-7.7 4.3 0 7.7 3.5 7.7 7.7 0 4.3-3.5 7.7-7.7 7.7zm4.7-9.5c0 1.3-1 2.3-2.3 2.3-1.3 0-2.3-1-2.3-2.3 0-1.3 1-2.3 2.3-2.3 1.3 0 2.3 1 2.3 2.3zm0 5.6c0 1.3-1 2.3-2.3 2.3-1.3 0-2.3-1-2.3-2.3 0-1.3 1-2.3 2.3-2.3 1.3 0 2.3 1 2.3 2.3zm-5.6 0c0 1.3-1 2.3-2.3 2.3-1.3 0-2.3-1-2.3-2.3 0-1.3 1-2.3 2.3-2.3 1.3 0 2.3 1 2.3 2.3zm0-5.6c0 1.3-1 2.3-2.3 2.3-1.3 0-2.3-1-2.3-2.3 0-1.3 1-2.3 2.3-2.3 1.3 0 2.3 1 2.3 2.3z" />
    </svg>
  );
}

export function ResendLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#ffffff" aria-label="Resend" {...props}>
      <path d="M5 4h7.5a4.5 4.5 0 0 1 1.99 8.54L18 20h-3.4l-3.2-7H8v7H5V4zm3 6.5h4.5a2 2 0 1 0 0-4H8v4z" />
    </svg>
  );
}

export function XaiLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#ffffff" aria-label="xAI" {...props}>
      <path d="M18.901 1.153h3.68l-8.04 9.19L24 22.846h-7.406l-5.8-7.584-6.638 7.584H.474l8.6-9.83L0 1.154h7.594l5.243 6.932ZM17.61 20.644h2.039L6.486 3.24H4.298Z" />
    </svg>
  );
}

export function PostHogLogo(props: LogoProps) {
  // PostHog's stacked-chevrons mark (the angular hedgehog-spike pattern)
  return (
    <svg viewBox="0 0 24 24" aria-label="PostHog" {...props}>
      <path
        d="M9.854 14.586 7.404 17.036a1.5 1.5 0 0 1-2.121-.001l-.793-.794a1.5 1.5 0 0 1 0-2.121l3.182-3.182zm-3.182 0 3.182 3.182-3.182 3.182H5.611a1.5 1.5 0 0 1-1.5-1.5v-3.182zm10-10 3.182 3.182v6.364l-3.182-3.182v-6.364zm-3.182 0 3.182 3.182-3.182 3.182H8.611a1.5 1.5 0 0 1-1.5-1.5V4.586zm-3.182 5L4 11v3.5l5.49-5.5z"
        fill="#f9bd2b"
      />
      {/* Eye dots */}
      <circle cx="14" cy="14" r="1.1" fill="#1d1f27" />
    </svg>
  );
}

export function SentryLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#a87aff" aria-label="Sentry" {...props}>
      <path d="M13.84 4.124c-.5-.86-1.74-.86-2.24 0L8.18 9.69a14 14 0 0 1 8.13 8.45h-2.74A11.32 11.32 0 0 0 6.74 12l-2.36 4.05a6.61 6.61 0 0 1 4.4 5.07H3.07a.43.43 0 0 1-.36-.65l1.83-3.13a4.04 4.04 0 0 0-1.45-.84l-1.79 3.06a2.6 2.6 0 0 0 2.25 3.91h6.4a8.78 8.78 0 0 0-5.49-7.93l1.18-2A11.32 11.32 0 0 1 11.81 21h7.13a14 14 0 0 0-8.59-13.21l1.84-3.18 5.83 10.07c-.66.36-1.27.78-1.85 1.26.52.49 1.02 1.01 1.5 1.55a8.85 8.85 0 0 1 2.4-1.21l1.36 2.36a2.6 2.6 0 0 0 .61-3.4z" />
    </svg>
  );
}

export function MistralLogo(props: LogoProps) {
  // Five horizontal "M" rows in Mistral's signature warm gradient
  return (
    <svg viewBox="0 0 24 24" aria-label="Mistral" {...props}>
      {/* Row 1 — yellow (top) */}
      <path d="M3.428 3.4h3.429v3.428H3.428zM17.143 3.4h3.429v3.428h-3.429z" fill="#ffd28a" />
      {/* Row 2 — light orange */}
      <path d="M3.428 6.828h6.857v3.429H3.428zM13.714 6.828h6.858v3.429h-6.858z" fill="#ffae00" />
      {/* Row 3 — orange (middle, the M crossbar) */}
      <path d="M3.428 10.258h17.143v3.428H3.428z" fill="#ff8205" />
      {/* Row 4 — red-orange */}
      <path d="M3.428 13.686h3.429v3.429H3.428zM10.286 13.686h3.428v3.429h-3.428zM17.143 13.686h3.429v3.429h-3.429z" fill="#fa520f" />
      {/* Row 5 — deep red (bottom) */}
      <path d="M3.428 17.115h3.429v3.428H3.428zM17.143 17.115h3.429v3.428h-3.429z" fill="#e10500" />
    </svg>
  );
}

export function ReplicateLogo(props: LogoProps) {
  // Replicate's three layered horizontal bars descending into vertical stems
  return (
    <svg viewBox="0 0 24 24" fill="#ffffff" aria-label="Replicate" {...props}>
      <path d="M3 3.5h18v3H8v14h-3V3.5z" />
      <path d="M5 8h16v3H10v9.5H7V8z" />
      <path d="M7 12.5h14v3h-9V20H9.5v-7.5z" />
    </svg>
  );
}

export function PerplexityLogo(props: LogoProps) {
  // Perplexity's official mark — angular asterisk / octagram in their
  // signature teal. SimpleIcons-accurate path.
  return (
    <svg viewBox="0 0 24 24" fill="#20b8cd" aria-label="Perplexity" {...props}>
      <path d="M22.3977 7.0896h-2.3106V.0676l-7.5094 6.3219V.1577h-1.1554v6.1331L4.4904 0v7.0896H1.6023v10.3976h2.8882V24l6.9233-6.0124v6.0124h1.1554v-6.0124L19.4904 24v-6.5128h2.9073V7.0896zM5.6451 2.4787l5.7765 5.0531v3.0205L5.6451 5.499V2.4787zm10.5772 0v3.0203l-5.7765 5.0533V7.5318l5.7765-5.0531zM2.7577 8.2455h7.4051l-7.4051 6.4296V8.2455zm2.8882 13.2885v-9.6328l5.7765 5.0531v4.5797l-5.7765 0zm10.5772 0V16.954l5.7765-5.0531v9.6328l-5.7765-.0001zm5.6566-7.0654l-7.4051-6.4296h7.4051v6.4296z" />
    </svg>
  );
}

export function DatadogLogo(props: LogoProps) {
  // Datadog's dog/paw silhouette — head with two ears + paw print accent
  return (
    <svg viewBox="0 0 24 24" aria-label="Datadog" {...props}>
      {/* Dog head (rounded triangle pointing down) */}
      <path
        d="M4 4l5 5-2 2 3 3-2 2 4 4 8-8L4 4z"
        fill="#9d6bd1"
      />
      {/* Eye accent */}
      <circle cx="14" cy="10" r="1.2" fill="#1d1f27" />
      {/* Tongue dot */}
      <circle cx="11" cy="13" r="0.8" fill="#ff70a0" />
    </svg>
  );
}

export function DiscordLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#5865f2" aria-label="Discord" {...props}>
      <path d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z" />
    </svg>
  );
}

export function ClerkLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#6c47ff" aria-label="Clerk" {...props}>
      <path d="M21.469 19.674l-3.286-3.286a.97.97 0 00-1.218-.121 6.066 6.066 0 01-6.726 0 .97.97 0 00-1.218.121L5.736 19.674a.974.974 0 00.144 1.501 11.99 11.99 0 0013.444 0 .974.974 0 00.145-1.501zm.005-15.353l-3.291 3.291a.97.97 0 01-1.219.122 6.06 6.06 0 00-8.93 2.71A6.057 6.057 0 007.13 16.45a.97.97 0 01-.122 1.218l-3.291 3.291a.972.972 0 01-1.502-.144 12 12 0 0119.66-13.847.971.971 0 01-.4 1.353zM12 15.6a3.6 3.6 0 100-7.2 3.6 3.6 0 000 7.2z" />
    </svg>
  );
}

export function SendGridLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" {...props}>
      <path d="M0 12.0016V24h11.9982v-7.9989H4.0011v-8H0V12.0016z" fill="#1a82e2" />
      <path d="M12.0016 7.999v8.0027h7.9988V8.0014L12.0017.0026 4 7.999h8.0014z" fill="#9dd4f3" />
    </svg>
  );
}

export function PineconeLogo(props: LogoProps) {
  // Pine cone — segmented triangular cone with stem
  return (
    <svg viewBox="0 0 24 24" fill="#ffffff" aria-label="Pinecone" {...props}>
      {/* Stem at top */}
      <path d="M11 2h2v3h-2z" />
      {/* Cone scales — three rows of segmented chevrons widening downward */}
      <path d="M12 5l-3 4h6l-3-4z" />
      <path d="M12 9l-5 4h10l-5-4z" />
      <path d="M12 13l-7 4h14l-7-4z" />
      {/* Base point */}
      <path d="M12 17l-3 5h6l-3-5z" />
    </svg>
  );
}

export function NeonLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#00e699" aria-label="Neon" {...props}>
      <path d="M0 4.8C0 2.149 2.149 0 4.8 0h14.4C21.851 0 24 2.149 24 4.8v11.4c0 2.298-2.866 3.337-4.331 1.572L15.6 13.115V19.2c0 2.651-2.149 4.8-4.8 4.8H4.8C2.149 24 0 21.851 0 19.2V4.8zm4.8-1.2a1.2 1.2 0 00-1.2 1.2v14.4a1.2 1.2 0 002.4 0V14.4c0-2.298 2.865-3.336 4.33-1.571l4.07 4.658V4.8a1.2 1.2 0 00-1.2-1.2H4.8z" />
    </svg>
  );
}

export function UpstashLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" fill="#00e9a3" aria-label="Upstash" {...props}>
      <path d="M5.625 18.375a8.969 8.969 0 0012.69 0l-1.689-1.69a6.578 6.578 0 01-9.31 0l-1.69 1.69zm3.378-3.378a4.188 4.188 0 005.945 0l-1.689-1.689a1.797 1.797 0 01-2.567 0l-1.689 1.69zm9.255-9.347a8.969 8.969 0 010 12.69l-1.69-1.689a6.578 6.578 0 000-9.31l1.69-1.69zM3.347 5.65a8.969 8.969 0 0012.69 0l-1.689 1.69a6.578 6.578 0 01-9.31 0L3.347 5.65zm3.379 3.378a4.188 4.188 0 005.945 0l-1.689 1.69a1.797 1.797 0 01-2.567 0l-1.69-1.69z" />
    </svg>
  );
}

/* ── Data ────────────────────────────────────────────────────── */

interface LogoEntry {
  Logo: (p: LogoProps) => React.JSX.Element;
  name: string;
  /** brand accent color used for the small dot beside the card */
  color: string;
  category: "ai" | "editor" | "infra" | "db" | "comms" | "dev" | "auth" | "obs";
  env: string;
  token: string;
}

export const KEY_ENTRIES: LogoEntry[] = [
  // AI APIs
  { Logo: OpenAILogo,     name: "OpenAI",      color: "#10a37f", category: "ai",     env: "OPENAI_API_KEY",      token: "phm_a8f2c4d9" },
  { Logo: ClaudeLogo,     name: "Anthropic",   color: "#cc785c", category: "ai",     env: "ANTHROPIC_API_KEY",   token: "phm_e1b773c0" },
  { Logo: XaiLogo,        name: "xAI",         color: "#ffffff", category: "ai",     env: "XAI_API_KEY",         token: "phm_4a91c70b" },
  { Logo: GeminiLogo,     name: "Gemini",      color: "#4285f4", category: "ai",     env: "GEMINI_API_KEY",      token: "phm_38d2e6a4" },
  { Logo: MistralLogo,    name: "Mistral",     color: "#ff7000", category: "ai",     env: "MISTRAL_API_KEY",     token: "phm_b6c1f827" },
  { Logo: PerplexityLogo, name: "Perplexity",  color: "#20b8cd", category: "ai",     env: "PERPLEXITY_API_KEY",  token: "phm_05fa9d3e" },
  { Logo: ReplicateLogo,  name: "Replicate",   color: "#ffffff", category: "ai",     env: "REPLICATE_API_TOKEN", token: "phm_e8c40b71" },

  // Editors
  { Logo: CursorLogo,     name: "Cursor",      color: "#ffffff", category: "editor", env: "CURSOR_API_KEY",      token: "phm_77b3e5f1" },
  { Logo: WindsurfLogo,   name: "Windsurf",    color: "#19b3a6", category: "editor", env: "WINDSURF_API_KEY",    token: "phm_1c9e2a40" },

  // Infra
  { Logo: VercelLogo,     name: "Vercel",      color: "#ffffff", category: "infra",  env: "VERCEL_TOKEN",        token: "phm_d9f1c102" },
  { Logo: RailwayLogo,    name: "Railway",     color: "#ffffff", category: "infra",  env: "RAILWAY_TOKEN",       token: "phm_8b4d6f93" },
  { Logo: AwsLogo,        name: "AWS",         color: "#ff9900", category: "infra",  env: "AWS_SECRET_KEY",      token: "phm_5e2a8d61" },
  { Logo: GcpLogo,        name: "GCP",         color: "#4285f4", category: "infra",  env: "GCP_API_KEY",         token: "phm_c7f9b203" },
  { Logo: CloudflareLogo, name: "Cloudflare",  color: "#f48120", category: "infra",  env: "CF_API_TOKEN",        token: "phm_ae15f627" },

  // Databases
  { Logo: SupabaseLogo,   name: "Supabase",    color: "#3ecf8e", category: "db",     env: "SUPABASE_KEY",        token: "phm_4f1c8ae3" },
  { Logo: PostgresLogo,   name: "Postgres",    color: "#5d8db0", category: "db",     env: "DATABASE_URL",        token: "phm_3a2e7c81" },
  { Logo: MongoLogo,      name: "MongoDB",     color: "#47a248", category: "db",     env: "MONGODB_URI",         token: "phm_6e0fb529" },
  { Logo: NeonLogo,       name: "Neon",        color: "#00e699", category: "db",     env: "NEON_API_KEY",        token: "phm_aa9d34f0" },
  { Logo: UpstashLogo,    name: "Upstash",     color: "#00e9a3", category: "db",     env: "UPSTASH_REDIS_TOKEN", token: "phm_3fc0e851" },
  { Logo: PineconeLogo,   name: "Pinecone",    color: "#ffffff", category: "db",     env: "PINECONE_API_KEY",    token: "phm_b71204e5" },

  // Commerce / comms
  { Logo: StripeLogo,     name: "Stripe",      color: "#635bff", category: "comms",  env: "STRIPE_SECRET_KEY",   token: "phm_2ccb5a91" },
  { Logo: TwilioLogo,     name: "Twilio",      color: "#f22f46", category: "comms",  env: "TWILIO_AUTH_TOKEN",   token: "phm_9d4b3e12" },
  { Logo: ResendLogo,     name: "Resend",      color: "#ffffff", category: "comms",  env: "RESEND_API_KEY",      token: "phm_f1a82b57" },
  { Logo: SendGridLogo,   name: "SendGrid",    color: "#1a82e2", category: "comms",  env: "SENDGRID_API_KEY",    token: "phm_2940bf16" },
  { Logo: SlackLogo,      name: "Slack",       color: "#e01e5a", category: "comms",  env: "SLACK_BOT_TOKEN",     token: "phm_71e0d493" },
  { Logo: DiscordLogo,    name: "Discord",     color: "#5865f2", category: "comms",  env: "DISCORD_BOT_TOKEN",   token: "phm_e74cb201" },

  // Auth
  { Logo: ClerkLogo,      name: "Clerk",       color: "#6c47ff", category: "auth",   env: "CLERK_SECRET_KEY",    token: "phm_8af216c3" },

  // Observability
  { Logo: PostHogLogo,    name: "PostHog",     color: "#f9bd2b", category: "obs",    env: "POSTHOG_API_KEY",     token: "phm_d2bf1e95" },
  { Logo: SentryLogo,     name: "Sentry",      color: "#a87aff", category: "obs",    env: "SENTRY_AUTH_TOKEN",   token: "phm_3187a4d0" },
  { Logo: DatadogLogo,    name: "Datadog",     color: "#9d6bd1", category: "obs",    env: "DATADOG_API_KEY",     token: "phm_f5e290bc" },

  // Dev
  { Logo: GitHubLogo,     name: "GitHub",      color: "#ffffff", category: "dev",    env: "GITHUB_TOKEN",        token: "phm_99a8d2bf" },
  { Logo: DockerLogo,     name: "Docker",      color: "#2496ed", category: "dev",    env: "DOCKER_TOKEN",        token: "phm_b5817d4c" },
  { Logo: NotionLogo,     name: "Notion",      color: "#ffffff", category: "dev",    env: "NOTION_API_KEY",      token: "phm_d04c1f86" },
  { Logo: LinearLogo,     name: "Linear",      color: "#5e6ad2", category: "dev",    env: "LINEAR_API_KEY",      token: "phm_e2f37a91" },
  { Logo: FigmaLogo,      name: "Figma",       color: "#f24e1e", category: "dev",    env: "FIGMA_TOKEN",         token: "phm_82bd5a14" },
];

export const LOGOS = KEY_ENTRIES.map(({ Logo, name }) => ({ Logo, name }));
