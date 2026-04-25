"use client";

import { motion, useReducedMotion } from "motion/react";
import { Lock } from "./Icons";

const REAL_KEY = "OPENAI_API_KEY=sk-proj-aB3xK9LmN2pQrT...";
const PHM_KEY = "OPENAI_API_KEY=phm_a8f2c4d9e1b7";

const LOOP_DURATION = 6.4;

export function TheSwap() {
  const reduce = useReducedMotion();

  return (
    <div
      aria-label="Animated diagram: real API key transforms into phantom token while real key is sealed in vault"
      className="swap-stage relative mx-auto w-full max-w-[640px] py-10 sm:py-14 select-none"
    >
      {/* Soft halo behind the card */}
      <div
        aria-hidden
        className="absolute inset-0 -z-10 mx-auto blur-3xl opacity-60"
        style={{
          background:
            "radial-gradient(ellipse at 50% 40%, rgba(59,130,246,0.18) 0%, transparent 60%)",
        }}
      />

      {/* The card that flips */}
      <motion.div
        className="swap-card relative mx-auto h-[112px] sm:h-[128px] w-full max-w-[520px]"
        initial={{ rotateY: 0 }}
        animate={
          reduce
            ? { rotateY: 180 }
            : {
                rotateY: [0, 0, 180, 180, 180, 0, 0],
              }
        }
        transition={
          reduce
            ? { duration: 0 }
            : {
                duration: LOOP_DURATION,
                ease: [0.65, 0, 0.35, 1],
                times: [0, 0.18, 0.36, 0.62, 0.78, 0.92, 1],
                repeat: Infinity,
                repeatDelay: 0,
              }
        }
        style={{ willChange: "transform" }}
      >
        {/* Front face — the real key */}
        <div className="swap-face absolute inset-0 rounded-2xl border border-border bg-s1/90 px-4 sm:px-6 py-5 sm:py-6 flex flex-col justify-center text-left shadow-2xl shadow-black/40">
          <div className="text-[0.62rem] sm:text-[0.68rem] uppercase tracking-[0.12em] font-semibold text-red/90 mb-2">
            Your real secret
          </div>
          <code className="text-[0.78rem] sm:text-[0.95rem] font-mono text-t1 break-all leading-relaxed">
            {REAL_KEY}
          </code>
        </div>

        {/* Back face — the phantom token */}
        <div className="swap-face swap-back absolute inset-0 rounded-2xl border border-blue-d bg-s1/90 px-4 sm:px-6 py-5 sm:py-6 flex flex-col justify-center text-left glow-blue">
          <div className="text-[0.62rem] sm:text-[0.68rem] uppercase tracking-[0.12em] font-semibold text-blue-b mb-2">
            What AI sees
          </div>
          <code className="text-[0.78rem] sm:text-[0.95rem] font-mono text-blue-b break-all leading-relaxed">
            {PHM_KEY}
          </code>
        </div>
      </motion.div>

      {/* Vault below */}
      <div className="relative mt-7 sm:mt-9 flex flex-col items-center">
        {/* Falling streak — real key being pulled into the vault */}
        <motion.div
          aria-hidden
          className="absolute -top-7 sm:-top-9 h-7 sm:h-9 w-px bg-gradient-to-b from-transparent via-blue/70 to-blue"
          initial={{ scaleY: 0, opacity: 0 }}
          animate={
            reduce
              ? { scaleY: 0, opacity: 0 }
              : {
                  scaleY: [0, 0, 1, 1, 0, 0, 0],
                  opacity: [0, 0, 1, 0.9, 0, 0, 0],
                }
          }
          transition={
            reduce
              ? { duration: 0 }
              : {
                  duration: LOOP_DURATION,
                  times: [0, 0.16, 0.28, 0.36, 0.44, 0.92, 1],
                  repeat: Infinity,
                }
          }
          style={{ transformOrigin: "top" }}
        />

        {/* Vault icon */}
        <motion.div
          className="relative h-14 w-14 sm:h-16 sm:w-16 rounded-2xl border border-border bg-s2 flex items-center justify-center"
          animate={
            reduce
              ? { scale: 1 }
              : {
                  scale: [1, 1, 1, 0.94, 1.02, 1, 1, 1],
                  borderColor: [
                    "var(--color-border)",
                    "var(--color-border)",
                    "var(--color-border)",
                    "var(--color-blue-d)",
                    "var(--color-blue-d)",
                    "var(--color-blue-d)",
                    "var(--color-border)",
                    "var(--color-border)",
                  ],
                }
          }
          transition={
            reduce
              ? { duration: 0 }
              : {
                  duration: LOOP_DURATION,
                  times: [0, 0.18, 0.32, 0.36, 0.42, 0.62, 0.92, 1],
                  repeat: Infinity,
                  ease: "easeInOut",
                }
          }
        >
          <Lock className="w-6 h-6 sm:w-7 sm:h-7 text-t2" />
          {/* Vault glow on lock */}
          <motion.div
            aria-hidden
            className="absolute inset-0 rounded-2xl"
            initial={{ opacity: 0 }}
            animate={
              reduce
                ? { opacity: 0 }
                : { opacity: [0, 0, 0, 0, 0.7, 0.4, 0.1, 0] }
            }
            transition={
              reduce
                ? { duration: 0 }
                : {
                    duration: LOOP_DURATION,
                    times: [0, 0.16, 0.32, 0.36, 0.42, 0.6, 0.85, 1],
                    repeat: Infinity,
                  }
            }
            style={{
              boxShadow:
                "0 0 0 1px rgba(59,130,246,0.5) inset, 0 0 36px -4px rgba(59,130,246,0.7)",
            }}
          />
        </motion.div>

        <p className="mt-3.5 text-[0.72rem] sm:text-[0.78rem] text-t3 tracking-wide">
          Sealed locally · OS keychain · ChaCha20-Poly1305
        </p>
      </div>
    </div>
  );
}
