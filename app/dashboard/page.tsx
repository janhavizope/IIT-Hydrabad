import Link from "next/link";
import { ArrowUpRight, ShieldAlert, Upload, Zap } from "lucide-react";
import AppShell from "@/components/app/AppShell";
import { Button } from "@/components/ui/button";

const metrics = [
  { label: "APKs analyzed", value: "48,291", change: "+12% this week" },
  { label: "Threats detected", value: "1,847", change: "97.4% accuracy" },
  { label: "Avg. scan time", value: "2.1s", change: "Pipeline healthy" },
] as const;

const recentScans = [
  { name: "com.fakebank.mobile.apk", risk: 87, status: "High" },
  { name: "com.noteslite.pro.apk", risk: 34, status: "Low" },
  { name: "com.flashvault.cleaner.apk", risk: 62, status: "Medium" },
] as const;

export default function DashboardPage() {
  return (
    <AppShell>
      <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="flex flex-col gap-6 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-sm font-medium text-primary">Dashboard</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-foreground">Threat operations</h1>
            <p className="mt-2 max-w-xl text-muted">
              Monitor scans, review risk scores, and act on GenAI-generated intelligence.
            </p>
          </div>
          <Button href="/upload" variant="primary">
            <Upload className="h-4 w-4" />
            Upload APK
          </Button>
        </div>

        <div className="mt-10 grid gap-4 sm:grid-cols-3">
          {metrics.map((metric) => (
            <div
              key={metric.label}
              className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-5"
            >
              <p className="text-sm text-muted">{metric.label}</p>
              <p className="mt-2 text-3xl font-semibold text-foreground">{metric.value}</p>
              <p className="mt-1 text-xs text-primary">{metric.change}</p>
            </div>
          ))}
        </div>

        <div className="mt-10 grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
          <section className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-6">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-foreground">Recent scans</h2>
              <Link href="/analysis" className="text-sm text-primary hover:text-primary/80">
                View all
              </Link>
            </div>
            <ul className="mt-5 divide-y divide-white/[0.06]">
              {recentScans.map((scan) => (
                <li key={scan.name} className="flex items-center justify-between gap-4 py-4 first:pt-0 last:pb-0">
                  <div>
                    <p className="font-mono text-sm text-foreground">{scan.name}</p>
                    <p className="mt-1 text-xs text-muted">Risk score {scan.risk}/100</p>
                  </div>
                  <span
                    className={`rounded-full px-2.5 py-1 text-xs font-medium ${
                      scan.status === "High"
                        ? "bg-red-400/10 text-red-300"
                        : scan.status === "Medium"
                          ? "bg-amber-400/10 text-amber-200"
                          : "bg-primary/10 text-primary"
                    }`}
                  >
                    {scan.status}
                  </span>
                </li>
              ))}
            </ul>
          </section>

          <section className="space-y-4">
            <div className="rounded-2xl border border-primary/20 bg-primary/5 p-6">
              <Zap className="h-5 w-5 text-primary" />
              <h3 className="mt-3 font-semibold text-foreground">Quick analysis</h3>
              <p className="mt-2 text-sm text-muted">
                Run static + dynamic analysis with GenAI reporting in one pipeline.
              </p>
              <Button href="/upload" variant="primary" size="sm" className="mt-4">
                Start scan
              </Button>
            </div>
            <div className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-6">
              <ShieldAlert className="h-5 w-5 text-secondary" />
              <h3 className="mt-3 font-semibold text-foreground">Threat intel</h3>
              <p className="mt-2 text-sm text-muted">2 new campaign matches in the last 24 hours.</p>
              <Link
                href="/threat-intel"
                className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-secondary hover:text-secondary/80"
              >
                Explore intel <ArrowUpRight className="h-4 w-4" />
              </Link>
            </div>
          </section>
        </div>
      </div>
    </AppShell>
  );
}
