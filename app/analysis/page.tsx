import AppShell from "@/components/app/AppShell";
import {
  AlertTriangle,
  CalendarDays,
  CheckCircle2,
  FileCode2,
  Fingerprint,
  Globe2,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  TriangleAlert,
  WifiOff,
} from "lucide-react";

type RiskLevel = "Green" | "Yellow" | "Orange" | "Red";

const apkInformation = [
  { label: "APK Name", value: "SecureBank Pro" },
  { label: "Package Name", value: "com.securebank.mobile" },
  { label: "Hash", value: "ab12c9f4d8e1f6a9" },
  { label: "File Size", value: "28.4 MB" },
  { label: "Scan Time", value: "14:32 UTC" },
  { label: "Analysis Engine", value: "Static + AI Threat Review" },
];

const permissions = [
  { name: "android.permission.INTERNET", status: "Granted", risk: "Green", note: "Required for backend connectivity and update sync." },
  { name: "android.permission.READ_SMS", status: "Granted", risk: "Red", note: "High-risk messaging access often linked to credential theft." },
  { name: "android.permission.RECEIVE_BOOT_COMPLETED", status: "Granted", risk: "Orange", note: "May indicate persistence behavior after reboot." },
  { name: "android.permission.SYSTEM_ALERT_WINDOW", status: "Granted", risk: "Red", note: "Overlay access is frequently abused for phishing." },
  { name: "android.permission.ACCESS_FINE_LOCATION", status: "Denied", risk: "Green", note: "Denied in current package manifest or runtime state." },
];

const suspiciousIndicators = [
  {
    title: "Obfuscated DEX payload",
    severity: "Red" as RiskLevel,
    icon: ShieldX,
    text: "Multiple classes are obfuscated, complicating static inspection and matching loader-based malware behavior.",
  },
  {
    title: "Overlay + SMS abuse",
    severity: "Red" as RiskLevel,
    icon: TriangleAlert,
    text: "The permission combination can be used to intercept messages and present deceptive overlays to the user.",
  },
  {
    title: "Encrypted endpoint strings",
    severity: "Orange" as RiskLevel,
    icon: WifiOff,
    text: "Network endpoints appear encrypted or concealed, reducing visibility into command-and-control activity.",
  },
  {
    title: "Suspicious bootstrap sequence",
    severity: "Yellow" as RiskLevel,
    icon: FileCode2,
    text: "Startup routines suggest staged loading and delayed execution commonly seen in trojanized APKs.",
  },
];

const recommendations = [
  {
    title: "Quarantine the sample",
    detail: "Move the APK to an isolated triage queue and block distribution until dynamic analysis is complete.",
    icon: ShieldAlert,
    tone: "border-red-400/20 bg-red-400/10 text-red-200",
  },
  {
    title: "Correlate with threat intel",
    detail: "Compare the hash, domain patterns, and code artifacts against known malware family signatures and sandbox verdicts.",
    icon: Globe2,
    tone: "border-cyan-400/20 bg-cyan-400/10 text-cyan-200",
  },
  {
    title: "Run dynamic validation",
    detail: "Execute the sample in a controlled sandbox with network capture, screen recording, and permission monitoring enabled.",
    icon: Sparkles,
    tone: "border-amber-400/20 bg-amber-400/10 text-amber-200",
  },
];

const aiSummary = [
  "This APK presents a high-confidence malicious profile due to the combination of SMS access, overlay permission usage, and obfuscated code paths.",
  "Static indicators are consistent with credential theft, persistence, and staged execution behavior. Further dynamic inspection is recommended before any trust decision.",
];

const riskScore = 92;

function getRiskBand(score: number): RiskLevel {
  if (score < 25) {
    return "Green";
  }

  if (score < 50) {
    return "Yellow";
  }

  if (score < 75) {
    return "Orange";
  }

  return "Red";
}

function getRiskColor(score: number) {
  switch (getRiskBand(score)) {
    case "Green":
      return "text-emerald-200";
    case "Yellow":
      return "text-yellow-200";
    case "Orange":
      return "text-orange-200";
    case "Red":
      return "text-red-200";
  }
}

function getRiskBadge(score: number) {
  switch (getRiskBand(score)) {
    case "Green":
      return "border-emerald-400/20 bg-emerald-400/10 text-emerald-200";
    case "Yellow":
      return "border-yellow-400/20 bg-yellow-400/10 text-yellow-200";
    case "Orange":
      return "border-orange-400/20 bg-orange-400/10 text-orange-200";
    case "Red":
      return "border-red-400/20 bg-red-400/10 text-red-200";
  }
}

function getRiskGradient(score: number) {
  switch (getRiskBand(score)) {
    case "Green":
      return "from-emerald-400 via-cyan-400 to-sky-500";
    case "Yellow":
      return "from-yellow-400 via-amber-400 to-orange-500";
    case "Orange":
      return "from-orange-400 via-orange-500 to-red-500";
    case "Red":
      return "from-red-400 via-rose-500 to-red-600";
  }
}

function getRiskIcon(score: number) {
  switch (getRiskBand(score)) {
    case "Green":
      return ShieldCheck;
    case "Yellow":
      return TriangleAlert;
    case "Orange":
      return ShieldAlert;
    case "Red":
      return ShieldX;
  }
}

export default function AnalysisPage() {
  const RiskIcon = getRiskIcon(riskScore);
  const riskBand = getRiskBand(riskScore);

  return (
    <AppShell>
      <div className="mx-auto max-w-6xl space-y-8 px-4 py-12 sm:px-6 lg:px-8">
        <section className="rounded-[2rem] border border-cyan-400/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-3">
              <p className="text-xs uppercase tracking-[0.34em] text-cyan-300/75">Analysis Report</p>
              <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">APK Analysis Results</h1>
              <p className="max-w-3xl text-sm leading-7 text-slate-300 sm:text-base">
                VirusTotal-style malware intelligence dashboard with package metadata, permission assessment, risk scoring, suspicious indicators, and analyst recommendations.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs uppercase tracking-[0.24em] text-slate-400">
              <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1">MobSF report</span>
              <span className={`rounded-full border px-3 py-1 ${getRiskBadge(riskScore)}`}>Risk {riskBand}</span>
            </div>
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <article className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.28em] text-cyan-300/75">APK Information</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Sample metadata</h2>
              </div>
              <div className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-xs text-slate-300">
                <Fingerprint className="mr-2 inline h-4 w-4" aria-hidden="true" />
                Static sample
              </div>
            </div>

            <div className="mt-6 grid gap-3 sm:grid-cols-2">
              {apkInformation.map((item) => (
                <div key={item.label} className="rounded-2xl border border-white/10 bg-slate-950/40 p-4 transition duration-300 hover:-translate-y-0.5 hover:border-cyan-400/20 hover:bg-white/[0.05]">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-400">{item.label}</p>
                  <p className="mt-2 break-words text-sm font-medium text-white">{item.value}</p>
                </div>
              ))}
            </div>

            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              {[
                { label: "Threat Level", value: "Critical", tone: "border-red-400/20 bg-red-400/10 text-red-200" },
                { label: "Confidence", value: "94%", tone: "border-orange-400/20 bg-orange-400/10 text-orange-200" },
                { label: "Verdict", value: "Block", tone: "border-cyan-400/20 bg-cyan-400/10 text-cyan-200" },
              ].map((item) => (
                <div key={item.label} className={`rounded-2xl border p-4 ${item.tone}`}>
                  <p className="text-[0.65rem] uppercase tracking-[0.24em] text-white/70">{item.label}</p>
                  <p className="mt-2 text-lg font-semibold text-white">{item.value}</p>
                </div>
              ))}
            </div>
          </article>

          <article className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.28em] text-cyan-300/75">Risk Score</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">0–100 meter</h2>
              </div>

              <span className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] ${getRiskBadge(riskScore)}`}>
                {riskBand}
              </span>
            </div>

            <div className="mt-6 rounded-[1.5rem] border border-white/10 bg-slate-950/40 p-5">
              <div className="flex items-end justify-between gap-4">
                <div>
                  <p className="text-sm uppercase tracking-[0.28em] text-slate-400">Risk Score</p>
                  <div className={`mt-2 text-5xl font-semibold tracking-tight ${getRiskColor(riskScore)}`}>{riskScore}</div>
                </div>
                <div className={`flex h-14 w-14 items-center justify-center rounded-2xl border ${getRiskBadge(riskScore)}`}>
                  <RiskIcon className="h-7 w-7" aria-hidden="true" />
                </div>
              </div>

              <div className="mt-5 h-4 overflow-hidden rounded-full bg-white/5">
                <div
                  className={`h-full rounded-full bg-gradient-to-r ${getRiskGradient(riskScore)} shadow-[0_0_25px_rgba(239,68,68,0.18)]`}
                  style={{ width: `${riskScore}%` }}
                />
              </div>

              <div className="mt-4 flex items-center justify-between text-xs uppercase tracking-[0.24em] text-slate-400">
                <span>0</span>
                <span>25</span>
                <span>50</span>
                <span>75</span>
                <span>100</span>
              </div>

              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Category</p>
                  <p className={`mt-2 text-lg font-semibold ${getRiskColor(riskScore)}`}>{riskBand}</p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Status</p>
                  <p className="mt-2 text-lg font-semibold text-white">Blocked for review</p>
                </div>
              </div>
            </div>
          </article>
        </section>

        <section className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <article className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.28em] text-cyan-300/75">Permissions Analysis</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Permission risk matrix</h2>
              </div>
              <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-xs text-slate-300">
                {permissions.length} permissions
              </span>
            </div>

            <div className="mt-6 overflow-hidden rounded-[1.5rem] border border-white/10">
              <table className="min-w-full divide-y divide-white/10 text-left text-sm">
                <thead className="bg-white/[0.03] text-slate-300">
                  <tr>
                    <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">Permission</th>
                    <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">Status</th>
                    <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10 text-slate-200">
                  {permissions.map((permission) => (
                    <tr key={permission.name} className="bg-transparent transition duration-300 hover:bg-white/[0.04]">
                      <td className="px-4 py-4 font-mono text-xs text-white sm:text-sm">{permission.name}</td>
                      <td className="px-4 py-4 text-slate-300">{permission.status}</td>
                      <td className="px-4 py-4">
                        <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] ${getRiskBadge(permission.risk === "Green" ? 10 : permission.risk === "Yellow" ? 35 : permission.risk === "Orange" ? 60 : 90)}`}>
                          {permission.risk}
                        </span>
                        <p className="mt-2 text-xs leading-5 text-slate-400">{permission.note}</p>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>

          <article className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
            <div>
              <p className="text-xs uppercase tracking-[0.28em] text-cyan-300/75">Risk Category</p>
              <h2 className="mt-2 text-2xl font-semibold text-white">Analysis disposition</h2>
            </div>

            <div className="mt-6 grid gap-3 sm:grid-cols-2">
              {[
                { label: "Risk Category", value: riskBand, tone: getRiskBadge(riskScore) },
                { label: "Action", value: "Escalate", tone: "border-red-400/20 bg-red-400/10 text-red-200" },
                { label: "Confidence", value: "High", tone: "border-orange-400/20 bg-orange-400/10 text-orange-200" },
                { label: "Disposition", value: "Block", tone: "border-cyan-400/20 bg-cyan-400/10 text-cyan-200" },
              ].map((item) => (
                <div key={item.label} className={`rounded-2xl border p-4 ${item.tone}`}>
                  <p className="text-[0.65rem] uppercase tracking-[0.24em] text-white/70">{item.label}</p>
                  <p className="mt-2 text-lg font-semibold text-white">{item.value}</p>
                </div>
              ))}
            </div>

            <div className="mt-6 rounded-2xl border border-white/10 bg-slate-950/40 p-4">
              <p className="text-sm text-slate-300">
                The sample is being treated as a high-confidence threat due to correlated static indicators, policy violations, and suspicious runtime behavior.
              </p>
            </div>
          </article>
        </section>

        <section className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <article className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.28em] text-cyan-300/75">Suspicious Indicators</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Top findings</h2>
              </div>
              <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-xs text-slate-300">
                Static indicators
              </span>
            </div>

            <div className="mt-6 grid gap-3">
              {suspiciousIndicators.map((indicator) => {
                const Icon = indicator.icon;

                return (
                  <div key={indicator.title} className="rounded-2xl border border-white/10 bg-slate-950/40 p-4 transition duration-300 hover:-translate-y-0.5 hover:border-cyan-400/20 hover:bg-white/[0.05]">
                    <div className="flex items-start gap-4">
                      <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border ${getRiskBadge(indicator.severity === "Green" ? 10 : indicator.severity === "Yellow" ? 35 : indicator.severity === "Orange" ? 60 : 90)}`}>
                        <Icon className="h-5 w-5" aria-hidden="true" />
                      </div>

                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-3">
                          <h3 className="text-sm font-semibold text-white">{indicator.title}</h3>
                          <span className={`rounded-full border px-2.5 py-1 text-[0.65rem] font-semibold uppercase tracking-[0.24em] ${getRiskBadge(indicator.severity === "Green" ? 10 : indicator.severity === "Yellow" ? 35 : indicator.severity === "Orange" ? 60 : 90)}`}>
                            {indicator.severity}
                          </span>
                        </div>
                        <p className="mt-2 text-sm leading-6 text-slate-300">{indicator.text}</p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </article>

          <article className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
            <div>
              <p className="text-xs uppercase tracking-[0.28em] text-cyan-300/75">AI Security Summary</p>
              <h2 className="mt-2 text-2xl font-semibold text-white">Analyst-grade interpretation</h2>
            </div>

            <div className="mt-6 space-y-4">
              {aiSummary.map((paragraph, index) => (
                <div key={paragraph} className="rounded-2xl border border-white/10 bg-slate-950/40 p-4">
                  <div className="flex items-start gap-3">
                    <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-400 via-sky-400 to-blue-500 text-sm font-semibold text-slate-950 shadow-[0_0_18px_rgba(34,211,238,0.2)]">
                      {index + 1}
                    </div>
                    <p className="text-sm leading-6 text-slate-200">{paragraph}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-6 rounded-2xl border border-white/10 bg-white/[0.03] p-4">
              <p className="text-xs uppercase tracking-[0.28em] text-slate-400">Observation</p>
              <p className="mt-2 text-sm leading-6 text-slate-200">
                The sample is strongly aligned with malicious droppers and phishing-oriented APKs. The score distribution suggests immediate containment rather than passive monitoring.
              </p>
            </div>
          </article>
        </section>

        <section className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-[0.28em] text-cyan-300/75">Recommendations</p>
              <h2 className="mt-2 text-2xl font-semibold text-white">Next actions</h2>
            </div>
            <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-xs text-slate-300">
              Analyst playbook
            </span>
          </div>

          <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {recommendations.map((item) => {
              const Icon = item.icon;

              return (
                <div key={item.title} className={`flex flex-col gap-4 rounded-2xl border p-5 ${item.tone}`}>
                  <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-white/15 bg-slate-950/50 text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]">
                    <Icon className="h-5 w-5" aria-hidden="true" />
                  </div>
                  <div className="space-y-2">
                    <h3 className="text-sm font-semibold text-white">{item.title}</h3>
                    <p className="text-sm leading-6 text-slate-200/90">{item.detail}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      </div>
    </AppShell>
  );
}