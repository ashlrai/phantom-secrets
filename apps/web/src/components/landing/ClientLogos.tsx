import type { SVGProps } from "react";
import type { IconBaseProps } from "react-icons";
import { SiClaude, SiOpenai, SiWindsurf } from "react-icons/si";

type LogoProps = SVGProps<SVGSVGElement>;

function asIconProps(props: LogoProps, color: string): IconBaseProps {
  return {
    color,
    className: props.className as string | undefined,
    style: props.style,
    "aria-label": props["aria-label"],
    "aria-hidden": props["aria-hidden"],
  };
}

export function ClaudeClientLogo(props: LogoProps) {
  return <SiClaude {...asIconProps(props, "#d97757")} />;
}

export function CursorClientLogo(props: LogoProps) {
  return (
    <svg viewBox="0 0 24 24" aria-label="Cursor" {...props}>
      <path d="M11.925 24l10.425-6-10.425-6L1.5 18l10.425 6z" fill="currentColor" opacity=".95" />
      <path d="M22.35 18V6L11.925 0v12l10.425 6z" fill="currentColor" opacity=".7" />
      <path d="M11.925 0L1.5 6v12l10.425-6V0z" fill="currentColor" />
    </svg>
  );
}

export function WindsurfClientLogo(props: LogoProps) {
  return <SiWindsurf {...asIconProps(props, "#19b3a6")} />;
}

export function CodexClientLogo(props: LogoProps) {
  return <SiOpenai {...asIconProps(props, "currentColor")} />;
}
