type RiskScoreCardProps = {
  score: number;
  level: string;
};

const riskStyles = {
  Low: {
    badge: "border-emerald-400/20 bg-emerald-400/10 text-emerald-200",
    indicator: "bg-emerald-400",
    label: "Low",
  },
  Medium: {
    badge: "border-yellow-400/20 bg-yellow-400/10 text-yellow-200",
    indicator: "bg-yellow-400",
    label: "Medium",
  },
  High: {
    badge: "border-orange-400/20 bg-orange-400/10 text-orange-200",
    indicator: "bg-orange-400",
    label: "High",
  },
  Critical: {
    badge: "border-red-400/20 bg-red-400/10 text-red-200",
    indicator: "bg-red-400",
    label: "Critical",
  },
} as const;

function getRiskLevel(score: number) {
  if (score <= 25) return "Low";
  if (score <= 50) return "Medium";
  if (score <= 75) return "High";
  return "Critical";
}

export default function RiskScoreCard({ score, level }: RiskScoreCardProps) {
  const computedLevel = getRiskLevel(score);
  const safeLevel = riskStyles[level as keyof typeof riskStyles] ? level : computedLevel;
  const styles = riskStyles[safeLevel as keyof typeof riskStyles];

  return (
    <article className="rounded-[1.75rem] border border-white/10 bg-white/[0.04] p-5 shadow-[0_18px_70px_rgba(2,6,23,0.32)] backdrop-blur-xl transition-all duration-300 hover:-translate-y-1 hover:border-cyan-400/20 hover:shadow-[0_28px_90px_rgba(34,211,238,0.12)] [.matrix_&]:border-green-700 [.matrix_&]:bg-gray-950 [.matrix_&]:text-green-400 [.matrix_&]:shadow-[0_0_30px_rgba(34,197,94,0.12)] [.matrix_&]:hover:border-green-700 [.matrix_&]:hover:shadow-[0_0_36px_rgba(34,197,94,0.2)]">
      <div className="h-1.5 w-16 rounded-full bg-gradient-to-r from-cyan-400 via-sky-400 to-blue-500" />

      <div className="mt-5 flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-medium uppercase tracking-[0.28em] text-slate-300 [.matrix_&]:text-green-400">Risk Score</p>
          <p className="mt-3 text-4xl font-semibold tracking-tight text-white [.matrix_&]:text-green-400">{score}</p>
        </div>

        <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold shadow-[0_0_18px_rgba(2,6,23,0.18)] ${styles.badge}`}>
          <span className={`mr-2 h-2.5 w-2.5 rounded-full ${styles.indicator}`} />
          {styles.label}
        </span>
      </div>

      <div className="mt-5 rounded-2xl border border-white/10 bg-slate-950/40 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] [.matrix_&]:border-green-700 [.matrix_&]:bg-green-950/40">
        <p className="text-xs uppercase tracking-[0.28em] text-slate-400 [.matrix_&]:text-green-700">Risk Level</p>
        <p className="mt-2 text-lg font-medium text-white [.matrix_&]:text-green-400">{styles.label}</p>
      </div>
    </article>
  );
}