"use client";

import { motion, useReducedMotion } from "framer-motion";
import SectionReveal from "./SectionReveal";

const routes = [
  { from: { x: 18, y: 42 }, to: { x: 52, y: 38 }, delay: 0 },
  { from: { x: 72, y: 35 }, to: { x: 48, y: 52 }, delay: 0.4 },
  { from: { x: 35, y: 58 }, to: { x: 78, y: 48 }, delay: 0.8 },
  { from: { x: 55, y: 28 }, to: { x: 62, y: 62 }, delay: 1.2 },
] as const;

const hotspots = [
  { x: 18, y: 42, label: "EU" },
  { x: 52, y: 38, label: "US" },
  { x: 72, y: 35, label: "APAC" },
  { x: 48, y: 52, label: "LATAM" },
] as const;

export default function ThreatMap() {
  const reduced = useReducedMotion();

  return (
    <section className="border-t border-white/[0.06] py-24">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <SectionReveal className="text-center">
          <p className="text-sm font-medium uppercase tracking-[0.2em] text-secondary">Global intel</p>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            Threat activity map
          </h2>
          <p className="mx-auto mt-4 max-w-2xl text-muted">
            Live attack routes correlated from sandbox telemetry and threat intelligence feeds.
          </p>
        </SectionReveal>

        <SectionReveal delay={0.1} className="mt-12">
          <div className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.02] p-4 sm:p-8">
            <svg viewBox="0 0 100 60" className="h-auto w-full" aria-label="World threat map">
              <defs>
                <linearGradient id="routeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#0EA5E9" stopOpacity="0.2" />
                  <stop offset="50%" stopColor="#00E5A8" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#7C3AED" stopOpacity="0.4" />
                </linearGradient>
              </defs>

              {/* Simplified continents */}
              <ellipse cx="22" cy="28" rx="14" ry="10" fill="rgba(255,255,255,0.04)" stroke="rgba(255,255,255,0.08)" />
              <ellipse cx="48" cy="26" rx="16" ry="11" fill="rgba(255,255,255,0.04)" stroke="rgba(255,255,255,0.08)" />
              <ellipse cx="72" cy="30" rx="18" ry="12" fill="rgba(255,255,255,0.04)" stroke="rgba(255,255,255,0.08)" />
              <ellipse cx="42" cy="48" rx="12" ry="8" fill="rgba(255,255,255,0.04)" stroke="rgba(255,255,255,0.08)" />

              {routes.map((route, i) => (
                <motion.line
                  key={i}
                  x1={route.from.x}
                  y1={route.from.y}
                  x2={route.to.x}
                  y2={route.to.y}
                  stroke="url(#routeGrad)"
                  strokeWidth="0.35"
                  strokeDasharray="2 2"
                  initial={{ pathLength: 0, opacity: 0 }}
                  animate={reduced ? { opacity: 0.6 } : { pathLength: 1, opacity: [0.3, 0.9, 0.3] }}
                  transition={{
                    duration: 2.5,
                    delay: route.delay,
                    repeat: Infinity,
                    ease: "easeInOut",
                  }}
                />
              ))}

              {hotspots.map((spot) => (
                <g key={spot.label}>
                  <circle cx={spot.x} cy={spot.y} r="1.2" fill="#00E5A8" opacity="0.9" />
                  <circle cx={spot.x} cy={spot.y} r="2.5" fill="none" stroke="#00E5A8" strokeOpacity="0.35">
                    {!reduced ? (
                      <animate attributeName="r" values="2;4;2" dur="3s" repeatCount="indefinite" />
                    ) : null}
                  </circle>
                </g>
              ))}
            </svg>

            <div className="mt-6 flex flex-wrap justify-center gap-6 text-xs text-muted">
              <span className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-primary" />
                Active campaigns
              </span>
              <span className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-secondary" />
                Attack routes
              </span>
              <span className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-accent" />
                Intel matches
              </span>
            </div>
          </div>
        </SectionReveal>
      </div>
    </section>
  );
}
