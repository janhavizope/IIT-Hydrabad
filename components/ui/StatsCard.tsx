import type { LucideIcon } from "lucide-react";

type MetricTone = "safe" | "malware" | "suspicious" | "info";

type StatsCardProps = {
  title: string;
  value: number;
  trend: string;
  status: string;
  tone: MetricTone;
  icon: LucideIcon;
};

const toneStyles: Record<MetricTone, { shell: string; icon: string; badge: string; trend: string }> = {
  safe: {
    shell: "border-emerald-400/15 hover:border-emerald-400/30 hover:shadow-[0_28px_90px_rgba(16,185,129,0.14)]",
    icon: "border-emerald-400/20 bg-emerald-400/10 text-emerald-200 shadow-[0_0_18px_rgba(16,185,129,0.12)]",
    badge: "border-emerald-400/20 bg-emerald-400/10 text-emerald-200",
    trend: "text-emerald-200",
  },
  malware: {
    shell: "border-red-400/15 hover:border-red-400/30 hover:shadow-[0_28px_90px_rgba(239,68,68,0.14)]",
    icon: "border-red-400/20 bg-red-400/10 text-red-200 shadow-[0_0_18px_rgba(239,68,68,0.12)]",
    badge: "border-red-400/20 bg-red-400/10 text-red-200",
    trend: "text-red-200",
  },
  suspicious: {
    shell: "border-yellow-400/15 hover:border-yellow-400/30 hover:shadow-[0_28px_90px_rgba(234,179,8,0.14)]",
    icon: "border-yellow-400/20 bg-yellow-400/10 text-yellow-200 shadow-[0_0_18px_rgba(234,179,8,0.12)]",
    badge: "border-yellow-400/20 bg-yellow-400/10 text-yellow-200",
    trend: "text-yellow-200",
  },
  info: {
    shell: "border-cyan-400/15 hover:border-cyan-400/30 hover:shadow-[0_28px_90px_rgba(34,211,238,0.14)]",
    icon: "border-cyan-400/20 bg-cyan-400/10 text-cyan-200 shadow-[0_0_18px_rgba(34,211,238,0.12)]",
    badge: "border-cyan-400/20 bg-cyan-400/10 text-cyan-200",
    trend: "text-cyan-200",
  },
};

export default function StatsCard({ title, value, trend, status, tone, icon: Icon }: StatsCardProps) {
  const styles = toneStyles[tone];

  return (
    <article className={`group relative overflow-hidden rounded-[1.75rem] border border-white/10 bg-white/[0.04] p-5 shadow-[0_18px_70px_rgba(2,6,23,0.32)] backdrop-blur-xl transition-all duration-300 hover:-translate-y-1 ${styles.shell} [.matrix_&]:border-green-700 [.matrix_&]:bg-gray-950 [.matrix_&]:text-green-400 [.matrix_&]:shadow-[0_0_30px_rgba(34,197,94,0.12)] [.matrix_&]:hover:border-green-700 [.matrix_&]:hover:shadow-[0_0_36px_rgba(34,197,94,0.2)]`}>
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent opacity-70" />
      <div className="flex items-start justify-between gap-4">
        <div className={`flex h-12 w-12 items-center justify-center rounded-2xl border ${styles.icon}`}>
          <Icon className="h-5 w-5" aria-hidden="true" />
        </div>

        <span className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] ${styles.badge}`}>
          {status}
        </span>
      </div>

      <div className="mt-5 h-1.5 w-16 rounded-full bg-gradient-to-r from-cyan-400 via-sky-400 to-blue-500 transition-all duration-300 group-hover:w-24" />

      <p className="mt-5 text-sm font-medium uppercase tracking-[0.28em] text-slate-300 [.matrix_&]:text-green-400">
        {title}
      </p>

      <div className="mt-4 flex items-end justify-between gap-4">
        <p className="text-3xl font-semibold tracking-tight text-white sm:text-4xl [.matrix_&]:text-green-400">
          {new Intl.NumberFormat("en-US").format(value)}
        </p>

        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${styles.trend} ${styles.badge}`}>
          {trend}
        </span>
      </div>
    </article>
  );
}