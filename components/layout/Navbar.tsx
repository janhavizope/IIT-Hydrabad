import { Bell, Search, UserCircle2 } from "lucide-react";

export default function Navbar() {
  return (
    <header className="sticky top-0 z-30 border-b border-cyan-400/10 bg-slate-950/75 backdrop-blur-2xl shadow-[0_12px_48px_rgba(2,6,23,0.35)]">
      <div className="flex flex-col gap-5 px-4 py-4 sm:px-6 lg:flex-row lg:items-center lg:justify-between lg:px-8">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-xs uppercase tracking-[0.34em] text-cyan-300/75">APK Malware Analyzer</p>
            <span className="rounded-full border border-emerald-400/20 bg-emerald-400/10 px-2.5 py-1 text-[0.65rem] font-medium uppercase tracking-[0.24em] text-emerald-200">
              SOC Online
            </span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">Security Operations Dashboard</h1>
          <p className="max-w-2xl text-sm leading-6 text-slate-300">
            Live malware telemetry, triage-ready APK intelligence, and review flows designed for rapid analyst decisions.
          </p>
        </div>

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center lg:flex-1 lg:justify-end">
          <label className="flex w-full items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-slate-300 shadow-[0_0_24px_rgba(2,6,23,0.3)] sm:max-w-md lg:w-full lg:max-w-lg">
            <Search className="h-5 w-5 shrink-0 text-slate-400" aria-hidden="true" />
            <input
              type="search"
              placeholder="Search APKs, hashes, packages..."
              className="w-full bg-transparent text-sm text-white placeholder:text-slate-500 focus:outline-none"
            />
          </label>

          <div className="flex items-center gap-3">
            <button
              type="button"
              aria-label="Notifications"
              className="flex h-12 w-12 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.04] text-slate-200 shadow-[0_0_24px_rgba(2,6,23,0.25)] transition duration-300 hover:-translate-y-0.5 hover:border-cyan-400/25 hover:bg-cyan-400/10 hover:text-cyan-200 hover:shadow-[0_0_28px_rgba(34,211,238,0.15)]"
            >
              <Bell className="h-5 w-5" aria-hidden="true" />
            </button>

            <button
              type="button"
              className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.04] px-3 py-2 pr-4 text-left shadow-[0_0_24px_rgba(2,6,23,0.22)] transition duration-300 hover:-translate-y-0.5 hover:border-cyan-400/20 hover:bg-white/[0.06] hover:shadow-[0_0_30px_rgba(34,211,238,0.12)]"
            >
              <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-400 to-blue-500 text-slate-950">
                <UserCircle2 className="h-5 w-5" aria-hidden="true" />
              </span>
              <span className="hidden sm:block">
                <span className="block text-sm font-medium text-white">Analyst</span>
                <span className="block text-xs text-slate-400">Security Team</span>
              </span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}