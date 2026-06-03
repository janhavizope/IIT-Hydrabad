"use client";

import { motion, useReducedMotion } from "framer-motion";
import { Activity, Globe, KeyRound, ShieldAlert, Smartphone } from "lucide-react";

const nodes = [
  { label: "Permissions", angle: -70, icon: ShieldAlert, color: "#00E5A8" },
  { label: "Network Calls", angle: -20, icon: Globe, color: "#0EA5E9" },
  { label: "API Secrets", angle: 35, icon: KeyRound, color: "#7C3AED" },
  { label: "Malware Indicators", angle: 95, icon: Activity, color: "#f87171" },
  { label: "Risk Score", angle: 155, icon: ShieldAlert, color: "#00E5A8" },
] as const;

const RADIUS = 148;

function polarToXY(angleDeg: number, radius: number) {
  const rad = (angleDeg * Math.PI) / 180;
  return {
    x: Math.cos(rad) * radius,
    y: Math.sin(rad) * radius,
  };
}

export default function HolographicVisual() {
  const reduced = useReducedMotion();

  return (
    <div className="relative mx-auto flex aspect-square w-full max-w-lg items-center justify-center">
      {/* Ambient particles */}
      {[...Array(6)].map((_, i) => (
        <span
          key={i}
          className="absolute h-1 w-1 rounded-full bg-primary/40 animate-float"
          style={{
            left: `${15 + i * 14}%`,
            top: `${10 + (i % 3) * 28}%`,
            animationDelay: `${i * 0.4}s`,
          }}
        />
      ))}

      <div className="absolute inset-8 rounded-full border border-white/[0.06] bg-[radial-gradient(circle,rgba(0,229,168,0.08),transparent_65%)]" />

      <motion.div
        className="absolute inset-12 rounded-full border border-dashed border-primary/20"
        animate={reduced ? undefined : { rotate: 360 }}
        transition={{ duration: 40, repeat: Infinity, ease: "linear" }}
      />

      {/* Connection lines */}
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 400 400" aria-hidden>
        {nodes.map((node) => {
          const { x, y } = polarToXY(node.angle, RADIUS);
          const cx = 200;
          const cy = 200;
          return (
            <line
              key={node.label}
              x1={cx}
              y1={cy}
              x2={cx + x}
              y2={cy + y}
              stroke={node.color}
              strokeOpacity={0.35}
              strokeWidth={1}
              strokeDasharray="6 6"
              className="animate-pulse-glow"
            />
          );
        })}
      </svg>

      {/* Orbiting nodes */}
      {nodes.map((node, index) => {
        const { x, y } = polarToXY(node.angle, RADIUS);
        const Icon = node.icon;

        return (
          <motion.div
            key={node.label}
            className="absolute left-1/2 top-1/2"
            style={{ x: x - 56, y: y - 20 }}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.15 + index * 0.08 }}
          >
            <div className="flex w-28 flex-col items-center gap-1.5 rounded-xl border border-white/10 bg-background/80 px-2 py-2 text-center backdrop-blur-md">
              <Icon className="h-4 w-4" style={{ color: node.color }} />
              <span className="text-[0.65rem] font-medium leading-tight text-muted">{node.label}</span>
            </div>
          </motion.div>
        );
      })}

      {/* Phone core */}
      <motion.div
        className="relative z-10 flex h-52 w-28 flex-col items-center rounded-[2rem] border border-white/15 bg-gradient-to-b from-white/[0.08] to-white/[0.02] p-3 shadow-[0_0_60px_rgba(0,229,168,0.15)] backdrop-blur-xl"
        animate={reduced ? undefined : { y: [0, -6, 0] }}
        transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
      >
        <div className="mb-3 h-1.5 w-10 rounded-full bg-white/20" />
        <div className="flex flex-1 w-full flex-col items-center justify-center gap-3 rounded-2xl border border-primary/20 bg-primary/5">
          <Smartphone className="h-10 w-10 text-primary" strokeWidth={1.5} />
          <div className="space-y-1.5 w-full px-2">
            <div className="h-1 w-full rounded-full bg-primary/30" />
            <div className="h-1 w-4/5 rounded-full bg-secondary/30" />
            <div className="h-1 w-3/5 rounded-full bg-accent/30" />
          </div>
        </div>
        <p className="mt-3 text-[0.6rem] uppercase tracking-[0.2em] text-primary">Scanning</p>
      </motion.div>

      <div className="absolute bottom-6 left-1/2 -translate-x-1/2 rounded-full border border-primary/20 bg-primary/10 px-4 py-1.5 text-xs font-medium text-primary">
        Risk Score: 87
      </div>
    </div>
  );
}
