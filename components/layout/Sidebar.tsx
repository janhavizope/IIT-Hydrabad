"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  BrainCircuit,
  ChartColumnBig,
  FileSearch,
  LayoutDashboard,
  Shield,
  ShieldCheck,
  Settings,
  Upload,
} from "lucide-react";

type NavigationItem = {
  label: string;
  href: string;
  icon: typeof LayoutDashboard;
};

const navigationItems: NavigationItem[] = [
  {
    label: "Dashboard",
    href: "/",
    icon: LayoutDashboard,
  },
  {
    label: "Upload APK",
    href: "/upload",
    icon: Upload,
  },
  {
    label: "Analysis Results",
    href: "/analysis-results",
    icon: FileSearch,
  },
  {
    label: "Reports",
    href: "/reports",
    icon: ChartColumnBig,
  },
  {
    label: "AI Insights",
    href: "/ai-insights",
    icon: BrainCircuit,
  },
  {
    label: "Settings",
    href: "/settings",
    icon: Settings,
  },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed inset-y-0 left-0 z-40 hidden w-72 border-r border-cyan-400/10 bg-slate-950/80 text-slate-100 shadow-[0_0_50px_rgba(2,6,23,0.55)] backdrop-blur-2xl ring-1 ring-white/5 lg:flex lg:flex-col">
      <div className="flex h-full flex-col px-5 py-6">
        <div className="rounded-[1.75rem] border border-white/10 bg-white/[0.04] p-5 shadow-[0_0_40px_rgba(34,211,238,0.08)] backdrop-blur-xl transition duration-300 hover:border-cyan-400/20 hover:shadow-[0_0_48px_rgba(34,211,238,0.12)]">
          <div className="flex items-center gap-3">
            <div
              className="relative flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-cyan-400/25 bg-slate-900/90 shadow-[inset_0_1px_0_rgba(255,255,255,0.08),0_8px_24px_rgba(34,211,238,0.18)]"
              aria-hidden="true"
            >
              <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-cyan-500/15 via-transparent to-blue-600/20" />
              <Shield className="relative h-6 w-6 text-cyan-300" strokeWidth={1.75} />
              <span className="absolute -bottom-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-md border border-slate-900 bg-emerald-500 text-emerald-950">
                <ShieldCheck className="h-2.5 w-2.5" strokeWidth={2.5} aria-hidden="true" />
              </span>
            </div>
            <div className="min-w-0">
              <p className="text-[0.65rem] uppercase tracking-[0.34em] text-cyan-300/70">APK Malware Analyzer</p>
              <h2 className="mt-1 text-xl font-semibold text-white">Threat Console</h2>
            </div>
          </div>

          <p className="mt-4 text-sm leading-6 text-slate-300">
            Track APK risk signals, review results, and move quickly from detection to analysis.
          </p>
        </div>

        <nav className="mt-6 space-y-2">
          {navigationItems.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href;

            return (
              <Link
                key={item.label}
                href={item.href}
                className={`group flex items-center gap-3 rounded-2xl border px-4 py-3 text-sm transition-all duration-300 ${
                  isActive
                    ? "border-cyan-400/20 bg-cyan-400/10 text-white shadow-[0_0_24px_rgba(34,211,238,0.12)] hover:-translate-y-0.5"
                    : "border-white/5 bg-white/[0.03] text-slate-300 hover:-translate-y-0.5 hover:border-cyan-400/15 hover:bg-white/[0.06] hover:text-white hover:shadow-[0_0_22px_rgba(2,6,23,0.3)]"
                }`}
              >
                <span
                  className={`flex h-10 w-10 items-center justify-center rounded-xl border ${
                    isActive
                      ? "border-cyan-400/20 bg-cyan-400/15 text-cyan-200 shadow-[0_0_20px_rgba(34,211,238,0.12)]"
                      : "border-white/5 bg-slate-900/70 text-slate-400 group-hover:border-cyan-400/15 group-hover:text-cyan-200"
                  }`}
                >
                  <Icon className="h-5 w-5" aria-hidden="true" />
                </span>
                <span className="font-medium">{item.label}</span>
                {isActive ? <span className="ml-auto h-2 w-2 rounded-full bg-cyan-300" /> : null}
              </Link>
            );
          })}
        </nav>

        <div className="mt-auto rounded-[1.75rem] border border-emerald-400/15 bg-emerald-400/10 p-5 shadow-[0_0_24px_rgba(34,197,94,0.08)] backdrop-blur-xl">
          <div className="flex items-center gap-3">
            <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-emerald-400/20 bg-emerald-400/15 text-emerald-200 shadow-[0_0_20px_rgba(16,185,129,0.12)]">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </span>
            <div>
              <p className="text-xs uppercase tracking-[0.28em] text-emerald-200/70">System Status</p>
              <p className="text-sm font-medium text-white">Scanning pipeline operational</p>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}