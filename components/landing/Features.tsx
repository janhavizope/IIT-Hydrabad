"use client";

import {
  Brain,
  FileCode2,
  Globe2,
  Radar,
  ScrollText,
  Shield,
} from "lucide-react";
import SectionReveal from "./SectionReveal";

const features = [
  {
    title: "Reverse Engineering",
    description: "AI-assisted decompilation and bytecode inspection for hidden payloads.",
    icon: FileCode2,
  },
  {
    title: "Static Analysis",
    description: "Permission models, manifest review, and cryptographic weakness detection.",
    icon: Shield,
  },
  {
    title: "Dynamic Analysis",
    description: "Sandbox execution with network capture and behavioral tracing.",
    icon: Radar,
  },
  {
    title: "AI Risk Scoring",
    description: "Weighted scoring from malware families, heuristics, and GenAI verdicts.",
    icon: Brain,
  },
  {
    title: "Threat Intelligence",
    description: "Cross-reference hashes and domains against global reputation feeds.",
    icon: Globe2,
  },
  {
    title: "GenAI Report Generation",
    description: "Executive summaries and analyst playbooks generated in seconds.",
    icon: ScrollText,
  },
] as const;

export default function Features() {
  return (
    <section className="border-t border-white/[0.06] py-24">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <SectionReveal>
          <p className="text-sm font-medium uppercase tracking-[0.2em] text-secondary">Capabilities</p>
          <h2 className="mt-3 max-w-2xl text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            Enterprise-grade mobile threat analysis
          </h2>
        </SectionReveal>

        <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((feature, index) => {
            const Icon = feature.icon;

            return (
              <SectionReveal key={feature.title} delay={index * 0.05}>
                <article className="group h-full rounded-2xl border border-white/[0.08] bg-white/[0.02] p-6 transition hover:border-white/15 hover:bg-white/[0.04]">
                  <Icon className="h-5 w-5 text-primary" strokeWidth={1.75} />
                  <h3 className="mt-4 text-lg font-semibold text-foreground">{feature.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-muted">{feature.description}</p>
                </article>
              </SectionReveal>
            );
          })}
        </div>
      </div>
    </section>
  );
}
