"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import {
  Environment,
  Float,
  RoundedBox,
  Text,
  Sparkles,
} from "@react-three/drei";
import {
  EffectComposer,
  Bloom,
  ChromaticAberration,
  Vignette,
} from "@react-three/postprocessing";
import { BlendFunction } from "postprocessing";
import * as THREE from "three";

const TOKEN_LABELS = [
  "phm_a8f2c4d9",
  "phm_e1b773c0",
  "phm_2ccb5a91",
  "phm_d9f1c102",
  "phm_99a8d2bf",
  "phm_4f1c8ae3",
];

const ACCENT = "#60a5fa";
const ACCENT_DEEP = "#3b82f6";

function CursorRig() {
  const target = useRef({ x: 0, y: 0 });
  const { camera } = useThree();

  useEffect(() => {
    const onMove = (e: PointerEvent) => {
      const x = (e.clientX / window.innerWidth) * 2 - 1;
      const y = (e.clientY / window.innerHeight) * 2 - 1;
      target.current = { x, y };
    };
    window.addEventListener("pointermove", onMove, { passive: true });
    return () => window.removeEventListener("pointermove", onMove);
  }, []);

  useFrame((_, delta) => {
    const damp = 1 - Math.exp(-delta * 4);
    camera.position.x += (target.current.x * 0.6 - camera.position.x) * damp;
    camera.position.y += (-target.current.y * 0.4 + 0.3 - camera.position.y) * damp;
    camera.lookAt(0, 0, 0);
  });

  return null;
}

function Vault() {
  const ref = useRef<THREE.Mesh>(null);
  const innerRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    const t = state.clock.elapsedTime;
    if (ref.current) {
      ref.current.rotation.y = t * 0.18;
      ref.current.rotation.x = Math.sin(t * 0.3) * 0.08;
    }
    if (innerRef.current) {
      innerRef.current.rotation.y = -t * 0.4;
      innerRef.current.rotation.z = t * 0.2;
    }
  });

  return (
    <group>
      {/* Inner glowing core — visible through the glass */}
      <mesh ref={innerRef}>
        <icosahedronGeometry args={[0.45, 0]} />
        <meshStandardMaterial
          color={ACCENT}
          emissive={ACCENT}
          emissiveIntensity={2.4}
          roughness={0.3}
          metalness={0.6}
        />
      </mesh>

      {/* The glass vault */}
      <RoundedBox
        ref={ref}
        args={[1.6, 1.6, 1.6]}
        radius={0.18}
        smoothness={6}
        creaseAngle={0.4}
      >
        <meshPhysicalMaterial
          color="#ffffff"
          metalness={0.1}
          roughness={0.05}
          transmission={1}
          thickness={1.1}
          ior={1.6}
          attenuationColor={ACCENT}
          attenuationDistance={2.4}
          iridescence={1}
          iridescenceIOR={1.4}
          iridescenceThicknessRange={[100, 400]}
          clearcoat={1}
          clearcoatRoughness={0.04}
          envMapIntensity={1.4}
        />
      </RoundedBox>
    </group>
  );
}

function TokenSlab({
  label,
  radius,
  speed,
  phase,
  tilt,
  yOffset,
}: {
  label: string;
  radius: number;
  speed: number;
  phase: number;
  tilt: number;
  yOffset: number;
}) {
  const groupRef = useRef<THREE.Group>(null);
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    const t = state.clock.elapsedTime * speed + phase;
    if (groupRef.current) {
      groupRef.current.position.x = Math.cos(t) * radius;
      groupRef.current.position.z = Math.sin(t) * radius;
      groupRef.current.position.y = yOffset + Math.sin(t * 1.3) * 0.12;
      // Always face the camera-ish, tilted slightly
      groupRef.current.lookAt(0, yOffset, 0);
      groupRef.current.rotation.y += Math.PI;
      groupRef.current.rotation.z = tilt + Math.sin(t * 0.6) * 0.05;
    }
    if (meshRef.current) {
      const mat = meshRef.current.material as THREE.MeshStandardMaterial;
      mat.emissiveIntensity = 0.8 + Math.sin(t * 1.7) * 0.4;
    }
  });

  return (
    <group ref={groupRef}>
      {/* Card body */}
      <RoundedBox
        ref={meshRef}
        args={[1.1, 0.32, 0.04]}
        radius={0.06}
        smoothness={4}
      >
        <meshStandardMaterial
          color="#0a0a14"
          emissive={ACCENT_DEEP}
          emissiveIntensity={1.0}
          roughness={0.3}
          metalness={0.7}
        />
      </RoundedBox>
      {/* Token text */}
      <Text
        position={[0, 0, 0.025]}
        fontSize={0.13}
        color={ACCENT}
        anchorX="center"
        anchorY="middle"
        font="https://fonts.gstatic.com/s/jetbrainsmono/v18/tDbY2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKxjPVmUsaaDhw.woff"
        characters="phm_0123456789abcdef"
        outlineWidth={0.004}
        outlineColor={ACCENT_DEEP}
      >
        {label}
      </Text>
    </group>
  );
}

function ParticleStream() {
  const points = useRef<THREE.Points>(null);

  const { positions, speeds } = useMemo(() => {
    const COUNT = 220;
    const positions = new Float32Array(COUNT * 3);
    const speeds = new Float32Array(COUNT);
    for (let i = 0; i < COUNT; i++) {
      const r = Math.random() * 0.32;
      const theta = Math.random() * Math.PI * 2;
      positions[i * 3] = Math.cos(theta) * r;
      positions[i * 3 + 1] = Math.random() * 5 - 1;
      positions[i * 3 + 2] = Math.sin(theta) * r;
      speeds[i] = 0.4 + Math.random() * 0.8;
    }
    return { positions, speeds };
  }, []);

  useFrame((_, delta) => {
    const geo = points.current?.geometry;
    if (!geo) return;
    const pos = geo.attributes.position.array as Float32Array;
    for (let i = 0; i < pos.length / 3; i++) {
      pos[i * 3 + 1] += speeds[i] * delta;
      if (pos[i * 3 + 1] > 4.2) {
        pos[i * 3 + 1] = -1.2;
        const r = Math.random() * 0.32;
        const theta = Math.random() * Math.PI * 2;
        pos[i * 3] = Math.cos(theta) * r;
        pos[i * 3 + 2] = Math.sin(theta) * r;
      }
    }
    geo.attributes.position.needsUpdate = true;
  });

  return (
    <points ref={points}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          args={[positions, 3]}
          count={positions.length / 3}
        />
      </bufferGeometry>
      <pointsMaterial
        color={ACCENT}
        size={0.045}
        transparent
        opacity={0.85}
        sizeAttenuation
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </points>
  );
}

function Scene() {
  return (
    <>
      <color attach="background" args={["#050508"]} />
      <fog attach="fog" args={["#050508", 6, 14]} />

      <ambientLight intensity={0.3} />
      <directionalLight position={[3, 4, 5]} intensity={1.6} color="#ffffff" />
      <directionalLight position={[-3, -2, -4]} intensity={0.8} color={ACCENT_DEEP} />
      <pointLight position={[0, 0, 0]} intensity={3} color={ACCENT} distance={4} />

      <Environment preset="city" environmentIntensity={0.6} />

      {/* Background sparkle field — soft, far behind everything */}
      <Sparkles
        count={140}
        scale={[14, 9, 6]}
        size={2.6}
        speed={0.18}
        opacity={0.55}
        color={ACCENT}
        position={[0, 0.2, -3]}
      />

      <Float floatIntensity={0.6} rotationIntensity={0.25} speed={0.9}>
        <Vault />
      </Float>

      {[
        { label: TOKEN_LABELS[0], radius: 2.6, speed: 0.32, phase: 0, tilt: 0.12, yOffset: 0.7 },
        { label: TOKEN_LABELS[1], radius: 2.45, speed: 0.32, phase: Math.PI * 0.85, tilt: -0.12, yOffset: -0.6 },
        { label: TOKEN_LABELS[2], radius: 2.7, speed: 0.32, phase: Math.PI * 1.4, tilt: 0.08, yOffset: 0.1 },
        { label: TOKEN_LABELS[3], radius: 3.0, speed: 0.22, phase: Math.PI * 0.4, tilt: -0.06, yOffset: 1.4 },
        { label: TOKEN_LABELS[4], radius: 3.0, speed: 0.22, phase: Math.PI * 1.7, tilt: 0.1, yOffset: -1.3 },
      ].map((t) => (
        <TokenSlab key={t.label} {...t} />
      ))}

      <ParticleStream />

      <CursorRig />

      <EffectComposer multisampling={0} enableNormalPass={false}>
        <Bloom
          intensity={0.85}
          luminanceThreshold={0.18}
          luminanceSmoothing={0.6}
          mipmapBlur
        />
        <ChromaticAberration
          offset={[0.0007, 0.0009]}
          radialModulation={false}
          modulationOffset={0}
          blendFunction={BlendFunction.NORMAL}
        />
        <Vignette eskil={false} offset={0.2} darkness={0.55} />
      </EffectComposer>
    </>
  );
}

export function Hero3DScene() {
  // Lazy-mount the canvas only after the component is in view to avoid
  // initialising WebGL on first paint.
  const containerRef = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState(false);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) {
          setActive(true);
          obs.disconnect();
        }
      },
      { rootMargin: "200px" },
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  return (
    <div
      ref={containerRef}
      className="relative mx-auto aspect-[4/3] w-full max-w-[760px]"
      aria-hidden
    >
      {/* Halo behind the canvas */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 -z-10 blur-3xl opacity-70"
        style={{
          background:
            "radial-gradient(ellipse at 50% 45%, rgba(59,130,246,0.32) 0%, transparent 65%)",
        }}
      />
      {active ? (
        <Canvas
          dpr={[1, 1.75]}
          gl={{
            antialias: true,
            alpha: true,
            powerPreference: "high-performance",
          }}
          camera={{ position: [0, 0.3, 5], fov: 45 }}
          style={{ width: "100%", height: "100%" }}
        >
          <Scene />
        </Canvas>
      ) : null}
    </div>
  );
}
