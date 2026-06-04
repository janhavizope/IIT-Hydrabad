"use client";

import { AlertTriangle, CheckCircle2, FileWarning } from "lucide-react";
import Link from "next/link";
import SectionReveal from "./SectionReveal";
import { Button } from "@/components/ui/button";

const permissions = ["SMS", "Accessibility", "Contacts"] as const;

export default function AnalysisPreview() {
  return (
    <section id="demo" className="border-t border-white/[0.06] py-24">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <SectionReveal className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-sm font-medium uppercase tracking-[0.2em] text-accent">Live preview</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
              Analysis output
            </h2>
          </div>
          <Button href="/analysis" variant="outline" size="sm">
            Open full report
          </Button>
        </SectionReveal>

        <SectionReveal delay={0.1}>
          <article className="mt-10 overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.02]">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/[0.08] px-6 py-4">
              <div>
                <p className="text-xs uppercase tracking-wider text-muted">Sample scan</p>
                <p className="mt-1 font-mono text-sm text-foreground">com.fakebank.mobile.apk</p>
              </div>
              <div className="flex items-center gap-2 rounded-full border border-red-400/20 bg-red-400/10 px-3 py-1 text-xs font-medium text-red-300">
                <AlertTriangle className="h-3.5 w-3.5" />
                High Risk
              </div>
            </div>

            <div className="grid gap-6 p-6 lg:grid-cols-[1fr_280px]">
              <div className="space-y-6">
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted">AI Summary</p>
                  <p className="mt-3 text-sm leading-7 text-foreground/90">
                    This application exhibits suspicious behavior patterns including excessive permission
                    requests and encrypted communication with external domains.
                  </p>
                </div>

                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted">Permissions flagged</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {permissions.map((perm) => (
                      <span
                        key={perm}
                        className="rounded-lg border border-amber-400/20 bg-amber-400/10 px-3 py-1.5 text-xs font-medium text-amber-200"
                      >
                        {perm}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  {[
                    { label: "Static analysis", status: "Complete", ok: true },
                    { label: "Dynamic sandbox", status: "Complete", ok: true },
                    { label: "Threat intel match", status: "2 families", ok: false },
                    { label: "GenAI report", status: "Ready", ok: true },
                  ].map((row) => (
                    <div
                      key={row.label}
                      className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-background/50 px-4 py-3"
                    >
                      <span className="text-sm text-muted">{row.label}</span>
                      <span className="flex items-center gap-1.5 text-sm text-foreground">
                        {row.ok ? (
                          <CheckCircle2 className="h-4 w-4 text-primary" />
                        ) : (
                          <FileWarning className="h-4 w-4 text-amber-400" />
                        )}
                        {row.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.08] bg-background/60 p-5">
                <p className="text-xs font-medium uppercase tracking-wider text-muted">Risk Score</p>
                <div className="mt-4 flex items-end gap-2">
                  <span className="text-5xl font-semibold text-foreground">87</span>
                  <span className="mb-2 text-lg text-muted">/100</span>
                </div>
                <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/[0.06]">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-amber-400 via-red-400 to-red-500"
                    style={{ width: "87%" }}
                  />
                </div>
                <p className="mt-4 text-xs leading-relaxed text-muted">
                  Escalation recommended. Correlates with banking trojan heuristics and overlay abuse patterns.
                </p>
                <Link
                  href="/upload"
                  className="mt-5 block text-center text-sm font-medium text-primary hover:text-primary/80"
                >
                  Run your own scan →
                </Link>
              </div>
            </div>
          </article>
        </SectionReveal>
      </div>
    </section>
  );
}
