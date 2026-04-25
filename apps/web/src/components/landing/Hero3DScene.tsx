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
];

const ACCENT = "#60a5fa";
const ACCENT_DEEP = "#3b82f6";
const ACCENT_BRIGHT = "#93c5fd";

function CursorRig() {
  const target = useRef({ x: 0, y: 0 });
  const { camera, size } = useThree();

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
    const tx = target.current.x * 0.55;
    const ty = -target.current.y * 0.35 + 0.15;
    camera.position.x += (tx - camera.position.x) * damp;
    camera.position.y += (ty - camera.position.y) * damp;
    camera.lookAt(0, 0, 0);
  });

  return null;
}

/* The central glowing vault — translucent iridescent shell with a pulsing core. */
function Vault() {
  const shellRef = useRef<THREE.Mesh>(null);
  const coreRef = useRef<THREE.Mesh>(null);
  const ringRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    const t = state.clock.elapsedTime;
    if (shellRef.current) {
      shellRef.current.rotation.y = t * 0.18;
      shellRef.current.rotation.x = Math.sin(t * 0.4) * 0.12;
    }
    if (coreRef.current) {
      coreRef.current.rotation.y = -t * 0.7;
      coreRef.current.rotation.z = t * 0.45;
      const pulse = 1 + Math.sin(t * 1.4) * 0.08;
      coreRef.current.scale.setScalar(pulse);
    }
    if (ringRef.current) {
      ringRef.current.rotation.z = -t * 0.25;
    }
  });

  return (
    <group>
      {/* Inner glowing core — visible through the shell */}
      <mesh ref={coreRef}>
        <icosahedronGeometry args={[0.6, 0]} />
        <meshStandardMaterial
          color={ACCENT_BRIGHT}
          emissive={ACCENT}
          emissiveIntensity={3.4}
          roughness={0.2}
          metalness={0.7}
        />
      </mesh>

      {/* Halo ring around the vault */}
      <mesh ref={ringRef} rotation={[Math.PI / 2.4, 0, 0]}>
        <torusGeometry args={[1.45, 0.012, 16, 200]} />
        <meshStandardMaterial
          color={ACCENT_BRIGHT}
          emissive={ACCENT_BRIGHT}
          emissiveIntensity={2.6}
          toneMapped={false}
        />
      </mesh>

      {/* The glass shell */}
      <RoundedBox
        ref={shellRef}
        args={[1.95, 1.95, 1.95]}
        radius={0.32}
        smoothness={8}
        creaseAngle={0.4}
      >
        <meshPhysicalMaterial
          color="#ffffff"
          metalness={0.05}
          roughness={0.02}
          transmission={1}
          thickness={1.4}
          ior={1.7}
          attenuationColor={ACCENT_DEEP}
          attenuationDistance={2.6}
          iridescence={1}
          iridescenceIOR={1.45}
          iridescenceThicknessRange={[120, 460]}
          clearcoat={1}
          clearcoatRoughness={0.03}
          envMapIntensity={1.6}
          specularIntensity={1}
          reflectivity={0.5}
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
  yOffset,
}: {
  label: string;
  radius: number;
  speed: number;
  phase: number;
  yOffset: number;
}) {
  const groupRef = useRef<THREE.Group>(null);
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    const t = state.clock.elapsedTime * speed + phase;
    if (groupRef.current) {
      groupRef.current.position.x = Math.cos(t) * radius;
      groupRef.current.position.z = Math.sin(t) * radius - 0.3;
      groupRef.current.position.y = yOffset + Math.sin(t * 1.2) * 0.18;
      groupRef.current.lookAt(0, yOffset, 0);
      groupRef.current.rotation.y += Math.PI;
      groupRef.current.rotation.z = Math.sin(t * 0.5) * 0.08;
    }
    if (meshRef.current) {
      const mat = meshRef.current.material as THREE.MeshStandardMaterial;
      mat.emissiveIntensity = 1.0 + Math.sin(t * 1.7) * 0.5;
    }
  });

  return (
    <group ref={groupRef}>
      {/* Card body */}
      <RoundedBox
        ref={meshRef}
        args={[1.4, 0.42, 0.05]}
        radius={0.08}
        smoothness={5}
      >
        <meshStandardMaterial
          color="#0a0a18"
          emissive={ACCENT_DEEP}
          emissiveIntensity={1.2}
          roughness={0.25}
          metalness={0.85}
        />
      </RoundedBox>
      {/* Subtle glow outline */}
      <mesh position={[0, 0, -0.03]} scale={1.04}>
        <planeGeometry args={[1.4, 0.42]} />
        <meshBasicMaterial color={ACCENT} transparent opacity={0.22} />
      </mesh>
      {/* Token text */}
      <Text
        position={[0, 0, 0.03]}
        fontSize={0.16}
        color={ACCENT_BRIGHT}
        anchorX="center"
        anchorY="middle"
        font="https://fonts.gstatic.com/s/jetbrainsmono/v18/tDbY2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKxjPVmUsaaDhw.woff"
        characters="phm_0123456789abcdef"
        outlineWidth={0.005}
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
    const COUNT = 280;
    const positions = new Float32Array(COUNT * 3);
    const speeds = new Float32Array(COUNT);
    for (let i = 0; i < COUNT; i++) {
      const r = Math.random() * 0.55;
      const theta = Math.random() * Math.PI * 2;
      positions[i * 3] = Math.cos(theta) * r;
      positions[i * 3 + 1] = Math.random() * 6 - 1.5;
      positions[i * 3 + 2] = Math.sin(theta) * r;
      speeds[i] = 0.5 + Math.random() * 1.0;
    }
    return { positions, speeds };
  }, []);

  useFrame((_, delta) => {
    const geo = points.current?.geometry;
    if (!geo) return;
    const pos = geo.attributes.position.array as Float32Array;
    for (let i = 0; i < pos.length / 3; i++) {
      pos[i * 3 + 1] += speeds[i] * delta;
      if (pos[i * 3 + 1] > 4.8) {
        pos[i * 3 + 1] = -1.8;
        const r = Math.random() * 0.55;
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
        color={ACCENT_BRIGHT}
        size={0.055}
        transparent
        opacity={0.85}
        sizeAttenuation
        depthWrite={false}
        blending={THREE.AdditiveBlending}
        toneMapped={false}
      />
    </points>
  );
}

function Scene() {
  return (
    <>
      <fog attach="fog" args={["#050508", 7, 16]} />

      <ambientLight intensity={0.35} />
      <directionalLight position={[4, 5, 6]} intensity={2.2} color="#ffffff" />
      <directionalLight position={[-4, -2, -5]} intensity={1.0} color={ACCENT_DEEP} />
      <pointLight position={[0, 0, 0]} intensity={4.5} color={ACCENT} distance={5} />
      <pointLight position={[3, 2, 3]} intensity={1.5} color={ACCENT_BRIGHT} distance={6} />

      <Environment preset="city" environmentIntensity={0.55} />

      {/* Far back sparkle field */}
      <Sparkles
        count={180}
        scale={[16, 10, 6]}
        size={3}
        speed={0.2}
        opacity={0.65}
        color={ACCENT}
        position={[0, 0, -3]}
      />

      <Float floatIntensity={0.7} rotationIntensity={0.2} speed={0.85}>
        <Vault />
      </Float>

      {/* Three orbiting tokens at offset radii / heights / phases */}
      <TokenSlab label={TOKEN_LABELS[0]} radius={2.85} speed={0.32} phase={0} yOffset={0.85} />
      <TokenSlab label={TOKEN_LABELS[1]} radius={2.7}  speed={0.32} phase={Math.PI * 0.78} yOffset={-0.7} />
      <TokenSlab label={TOKEN_LABELS[2]} radius={3.05} speed={0.26} phase={Math.PI * 1.45} yOffset={0.05} />

      <ParticleStream />

      <CursorRig />

      <EffectComposer multisampling={0} enableNormalPass={false}>
        <Bloom
          intensity={1.2}
          luminanceThreshold={0.15}
          luminanceSmoothing={0.7}
          mipmapBlur
        />
        <ChromaticAberration
          offset={[0.0009, 0.0011]}
          radialModulation={false}
          modulationOffset={0}
          blendFunction={BlendFunction.NORMAL}
        />
        <Vignette eskil={false} offset={0.18} darkness={0.6} />
      </EffectComposer>
    </>
  );
}

export function Hero3DScene() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState(false);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    // Mount immediately if the container is already in the viewport
    // (hero is above the fold so this is the common case).
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight + 200) {
      setActive(true);
      return;
    }
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
      className="relative mx-auto aspect-square w-full max-w-[560px] lg:max-w-none lg:aspect-[5/6] lg:h-[600px]"
      aria-hidden
    >
      {/* Soft halo behind the canvas */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 -z-10 blur-3xl opacity-80"
        style={{
          background:
            "radial-gradient(ellipse at 50% 45%, rgba(59,130,246,0.42) 0%, transparent 65%)",
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
          camera={{ position: [0, 0.15, 5.2], fov: 42 }}
          style={{ width: "100%", height: "100%" }}
        >
          <Scene />
        </Canvas>
      ) : null}
    </div>
  );
}
