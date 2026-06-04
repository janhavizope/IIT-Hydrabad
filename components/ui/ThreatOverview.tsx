"use client";

const TOTAL_APKS = 1525;

const threatOverviewData = [
  { name: "High Risk APKs", value: 214, color: "#ef4444" },
  { name: "Medium Risk APKs", value: 298, color: "#f59e0b" },
  { name: "Safe APKs", value: 940, color: "#22c55e" },
  { name: "Unknown APKs", value: 73, color: "#38bdf8" },
] as const;

const severityLegend = [
  { label: "High Risk APKs", color: "bg-red-400", tone: "text-red-200" },
  { label: "Medium Risk APKs", color: "bg-amber-400", tone: "text-amber-200" },
  { label: "Safe APKs", color: "bg-emerald-400", tone: "text-emerald-200" },
  { label: "Unknown APKs", color: "bg-cyan-400", tone: "text-cyan-200" },
] as const;

const maxBarValue = Math.max(...threatOverviewData.map((d) => d.value));

function buildConicGradient() {
  let cumulative = 0;
  const stops: string[] = [];

  for (const segment of threatOverviewData) {
    const start = (cumulative / TOTAL_APKS) * 100;
    cumulative += segment.value;
    const end = (cumulative / TOTAL_APKS) * 100;
    stops.push(`${segment.color} ${start}% ${end}%`);
  }

  return `conic-gradient(from -90deg, ${stops.join(", ")})`;
}

function DonutChart() {
  const gradient = buildConicGradient();

  return (
    <div className="flex flex-col items-center justify-center py-2">
      <div
        className="relative flex h-56 w-56 items-center justify-center rounded-full shadow-[0_0_40px_rgba(34,211,238,0.08)]"
        style={{ background: gradient }}
        role="img"
        aria-label="APK risk distribution donut chart"
      >
        <div className="flex h-[58%] w-[58%] flex-col items-center justify-center rounded-full border border-white/10 bg-slate-950 text-center shadow-inner">
          <p className="text-[0.65rem] uppercase tracking-[0.28em] text-slate-400">Total</p>
          <p className="mt-1 text-3xl font-semibold text-white">{TOTAL_APKS.toLocaleString()}</p>
          <p className="mt-1 text-xs text-slate-400">APKs scanned</p>
        </div>
      </div>
    </div>
  );
}

function BarChartPanel() {
  return (
    <div className="flex h-72 flex-col justify-center gap-5 py-2">
      {threatOverviewData.map((entry) => {
        const widthPercent = Math.round((entry.value / maxBarValue) * 100);

        return (
          <div key={entry.name} className="grid grid-cols-[5.5rem_1fr_2.5rem] items-center gap-3">
            <span className="text-xs font-medium text-slate-300">{entry.name.replace(" APKs", "")}</span>
            <div className="h-6 overflow-hidden rounded-full bg-white/[0.06]">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${widthPercent}%`,
                  backgroundColor: entry.color,
                  boxShadow: `0 0 16px ${entry.color}55`,
                }}
              />
            </div>
            <span className="text-right text-sm font-semibold text-white">{entry.value}</span>
          </div>
        );
      })}
    </div>
  );
}

export default function ThreatOverview() {
  return (
    <section className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-cyan-300/75">Threat Overview</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">Risk distribution dashboard</h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
            Breakdown of APK posture across the active analysis window with severity color coding and analyst-ready context.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs uppercase tracking-[0.22em] text-slate-400">
          <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1">Live dataset</span>
          <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-cyan-200">Live view</span>
        </div>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[1.05fr_1.2fr]">
        <div className="rounded-[1.5rem] border border-white/10 bg-slate-950/40 p-5">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-[0.28em] text-slate-400">Donut chart</p>
              <h3 className="mt-2 text-lg font-semibold text-white">APK risk posture</h3>
            </div>
            <span className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs text-slate-300">
              {TOTAL_APKS.toLocaleString()} total
            </span>
          </div>

          <DonutChart />

          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            {severityLegend.map((item) => (
              <div key={item.label} className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3">
                <span className={`h-3 w-3 rounded-full ${item.color}`} />
                <span className={`text-sm font-medium ${item.tone}`}>{item.label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-[1.5rem] border border-white/10 bg-slate-950/40 p-5">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-[0.28em] text-slate-400">Risk distribution chart</p>
              <h3 className="mt-2 text-lg font-semibold text-white">Volume by severity</h3>
            </div>
            <span className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs text-slate-300">
              Current snapshot
            </span>
          </div>

          <BarChartPanel />

          <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {threatOverviewData.map((entry) => (
              <div key={entry.name} className="rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3">
                <p className="text-xs uppercase tracking-[0.24em] text-slate-400">{entry.name}</p>
                <p className="mt-2 text-lg font-semibold text-white">{entry.value}</p>
                <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${Math.max(14, Math.min(100, Math.round((entry.value / TOTAL_APKS) * 100)))}%`,
                      backgroundColor: entry.color,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
