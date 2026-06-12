"use client";

import { Brain, FileSearch, Gauge, Upload } from "lucide-react";
import SectionReveal from "./SectionReveal";

const steps = [
  {
    step: "01",
    title: "Upload APK",
    description: "Securely submit Android packages through our encrypted intake pipeline.",
    icon: Upload,
  },
  {
    step: "02",
    title: "AI Reverse Engineering",
    description: "GenAI decompiles and maps application structure, secrets, and control flow.",
    icon: Brain,
  },
  {
    step: "03",
    title: "Static + Dynamic Analysis",
    description: "Correlate permissions, network behavior, and runtime signals in one pass.",
    icon: FileSearch,
  },
  {
    step: "04",
    title: "Risk Score & Report",
    description: "Receive an investor-ready threat report with actionable intelligence.",
    icon: Gauge,
  },
] as const;

export default function Workflow() {
  return (
    <section id="how-it-works" className="border-t border-white/[0.06] py-24">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <SectionReveal className="text-center">
          <p className="text-sm font-medium uppercase tracking-[0.2em] text-primary">Process</p>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            How APK Shield Works
          </h2>
        </SectionReveal>

        <div className="mt-14 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {steps.map((item, index) => {
            const Icon = item.icon;

            return (
              <SectionReveal key={item.step} delay={index * 0.08}>
                <article className="group relative h-full rounded-2xl border border-white/[0.08] bg-white/[0.02] p-6 transition-all duration-300 hover:-translate-y-1 hover:border-primary/25 hover:bg-white/[0.04] hover:shadow-[0_8px_40px_rgba(0,229,168,0.08)]">
                  <span className="text-xs font-medium text-muted">{item.step}</span>
                  <div className="mt-4 flex h-11 w-11 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04] text-primary transition-colors group-hover:border-primary/30 group-hover:bg-primary/10">
                    <Icon className="h-5 w-5" />
                  </div>
                  <h3 className="mt-5 text-lg font-semibold text-foreground">{item.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-muted">{item.description}</p>
                </article>
              </SectionReveal>
            );
          })}
        </div>
      </div>
    </section>
  );
}
