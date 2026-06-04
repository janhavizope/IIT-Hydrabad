"use client";

import { ArrowRight, Play } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import HolographicVisual from "./HolographicVisual";

const stats = [
  { value: "48K+", label: "APKs analyzed" },
  { value: "97.4%", label: "Detection accuracy" },
  { value: "2.1s", label: "Average scan time" },
] as const;

export default function Hero() {
  const reduced = useReducedMotion();

  return (
    <section className="relative overflow-hidden pt-[72px]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(0,229,168,0.12),transparent)]" />
      <div className="pointer-events-none absolute right-0 top-1/4 h-96 w-96 rounded-full bg-secondary/10 blur-[120px]" />
      <div className="pointer-events-none absolute left-0 bottom-0 h-72 w-72 rounded-full bg-accent/10 blur-[100px]" />

      <div className="mx-auto grid max-w-7xl gap-12 px-4 py-20 sm:px-6 lg:grid-cols-2 lg:items-center lg:gap-16 lg:px-8 lg:py-28">
        <motion.div
          initial={reduced ? false : { opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <Badge>GenAI-powered Reverse Engineering</Badge>

          <h1 className="mt-6 text-4xl font-semibold leading-[1.1] tracking-tight text-foreground sm:text-5xl lg:text-[3.25rem]">
            Harnessing Generative AI for Automated APK Threat Detection
          </h1>

          <p className="mt-6 max-w-xl text-lg leading-relaxed text-muted">
            Analyze fraudulent mobile applications using AI-driven reverse engineering, static analysis,
            dynamic analysis, and automated risk scoring.
          </p>

          <div className="mt-8 flex flex-wrap gap-3">
            <Button href="/upload" variant="primary" size="lg">
              Upload APK
              <ArrowRight className="h-4 w-4" />
            </Button>
            <Button href="/dashboard" variant="secondary" size="lg">
              <Play className="h-4 w-4" />
              View Demo
            </Button>
          </div>

          <dl className="mt-12 grid grid-cols-3 gap-6 border-t border-white/10 pt-10">
            {stats.map((stat) => (
              <div key={stat.label}>
                <dt className="text-2xl font-semibold text-foreground sm:text-3xl">{stat.value}</dt>
                <dd className="mt-1 text-sm text-muted">{stat.label}</dd>
              </div>
            ))}
          </dl>
        </motion.div>

        <motion.div
          initial={reduced ? false : { opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.7, delay: 0.15 }}
          className="relative"
        >
          <HolographicVisual />
        </motion.div>
      </div>
    </section>
  );
}
