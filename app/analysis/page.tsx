"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import AppShell from "@/components/app/AppShell";
import {
  AlertTriangle,
  Fingerprint,
  Globe2,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  TriangleAlert,
  LoaderCircle,
  FileCode2
} from "lucide-react";

type RiskLevel = "Green" | "Yellow" | "Orange" | "Red";

function getRiskBand(score: number): RiskLevel {
  if (score < 25) return "Green";
  if (score < 50) return "Yellow";
  if (score < 75) return "Orange";
  return "Red";
}

function getRiskColor(score: number) {
  switch (getRiskBand(score)) {
    case "Green": return "text-emerald-200";
    case "Yellow": return "text-yellow-200";
    case "Orange": return "text-orange-200";
    case "Red": return "text-red-200";
  }
}

function getRiskBadge(score: number) {
  switch (getRiskBand(score)) {
    case "Green": return "border-emerald-400/20 bg-emerald-400/10 text-emerald-200";
    case "Yellow": return "border-yellow-400/20 bg-yellow-400/10 text-yellow-200";
    case "Orange": return "border-orange-400/20 bg-orange-400/10 text-orange-200";
    case "Red": return "border-red-400/20 bg-red-400/10 text-red-200";
  }
}

function getRiskGradient(score: number) {
  switch (getRiskBand(score)) {
    case "Green": return "from-emerald-400 via-cyan-400 to-sky-500";
    case "Yellow": return "from-yellow-400 via-amber-400 to-orange-500";
    case "Orange": return "from-orange-400 via-orange-500 to-red-500";
    case "Red": return "from-red-400 via-rose-500 to-red-600";
  }
}

function getRiskIcon(score: number) {
  switch (getRiskBand(score)) {
    case "Green": return ShieldCheck;
    case "Yellow": return TriangleAlert;
    case "Orange": return ShieldAlert;
    case "Red": return ShieldX;
  }
}

function AnalysisContent() {
  const searchParams = useSearchParams();
  const report_id = searchParams.get("report_id");
  
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!report_id) {
      setError("No report ID specified in URL parameter.");
      setLoading(false);
      return;
    }

    const pollAnalysis = () => {
        fetch(`http://localhost:8000/api/analyze-apk/${report_id}`)
          .then((res) => {
            if (!res.ok) throw new Error(`HTTP error ${res.status}`);
            return res.json();
          })
          .then((json) => {
            if (json.status === "failed") {
              setError(json.error_message || "Analysis pipeline failed.");
              setLoading(false);
            } else if (json.status === "PENDING") {
              setTimeout(pollAnalysis, 5000);
            } else {
              setData(json);
              setLoading(false);
            }
          })
          .catch((err) => {
            console.error(err);
            setError("Network error fetching analysis. Ensure backend is running.");
            setLoading(false);
          });
    };
    
    pollAnalysis();
  }, [report_id]);

  if (loading) {
    return (
      <div className="flex h-[60vh] flex-col items-center justify-center gap-5 text-slate-300">
        <LoaderCircle className="h-12 w-12 animate-spin text-cyan-400" />
        <div className="text-center">
            <p className="text-lg font-medium text-white">Analyzing APK...</p>
            <p className="mt-2 text-sm text-slate-400">Static and dynamic analysis may take up to 30 seconds.</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex h-[60vh] flex-col items-center justify-center gap-4 text-red-400">
        <ShieldX className="h-12 w-12" />
        <p className="text-lg font-medium">{error}</p>
      </div>
    );
  }

  const riskScore = data.final_verdict?.final_risk_score || 0;
  const verdict = data.final_verdict?.verdict || "UNKNOWN";
  const confidence = data.final_verdict?.confidence || 0;
  const RiskIcon = getRiskIcon(riskScore);
  const riskBand = getRiskBand(riskScore);

  const apkInformation = [
    { label: "Report ID", value: report_id },
    { label: "Package Name", value: data.package_name || "Unknown" },
    { label: "Hash (SHA256)", value: data.apk_hash || "Unknown" },
    { label: "Veridct", value: verdict },
    { label: "Confidence", value: `${Math.round(confidence * 100)}%` },
    { label: "Analysis Engine", value: "Static + Sandbox Fusion" },
  ];

  const dangerousPerms = data.static_analysis?.permissions?.dangerous || [];
  const allPerms = data.permissions || [];
  
  const mappedPermissions = allPerms.map((p: string) => {
      const isDangerous = dangerousPerms.includes(p) || p.includes("SMS") || p.includes("CONTACTS") || p.includes("LOCATION");
      return {
          name: p,
          status: "Granted",
          risk: isDangerous ? "Red" : "Green",
          note: isDangerous ? "Flagged as high-risk permission by static engine." : "Standard system permission."
      };
  });

  const suspiciousIndicators = [];
  
  const iocs = data.static_analysis?.extracted_iocs || {};
  if (iocs.urls?.length > 0 || iocs.ips?.length > 0 || iocs.apikeys?.length > 0) {
      suspiciousIndicators.push({
          title: "Hardcoded IOCs Detected",
          severity: "Red" as RiskLevel,
          icon: Globe2,
          text: `Found ${iocs.urls?.length || 0} URLs, ${iocs.ips?.length || 0} IPs, and ${iocs.apikeys?.length || 0} API keys hardcoded in the code.`
      });
  }

  if (data.dynamic_analysis?.behavior_risk?.attack_patterns?.length > 0 || data.dynamic_analysis?.attack_patterns?.length > 0) {
      const p = data.dynamic_analysis.behavior_risk?.attack_patterns || data.dynamic_analysis.attack_patterns;
      suspiciousIndicators.push({
          title: "Suspicious Runtime Behaviors",
          severity: "Red" as RiskLevel,
          icon: ShieldAlert,
          text: `Sandbox automation detected: ${p.join(", ")}`
      });
  }

  if (data.static_analysis?.attack_patterns?.length > 0) {
       suspiciousIndicators.push({
          title: "Attack Patterns Detected",
          severity: "Orange" as RiskLevel,
          icon: FileCode2,
          text: `Static analysis detected: ${data.static_analysis.attack_patterns.join(", ")}`
      });
  }

  if (dangerousPerms.length > 0) {
      suspiciousIndicators.push({
          title: "Dangerous Permission Profile",
          severity: "Orange" as RiskLevel,
          icon: TriangleAlert,
          text: `Application requests ${dangerousPerms.length} permissions known to be abused by malware.`
      });
  }

  if (suspiciousIndicators.length === 0) {
      suspiciousIndicators.push({
          title: "No Major Indicators",
          severity: "Green" as RiskLevel,
          icon: ShieldCheck,
          text: "The analysis engine did not detect any immediate attack patterns or malicious behaviors."
      });
  }

  const aiSummary = data.final_verdict?.reasoning || [
      "Analysis complete. See dashboard for specific indicators."
  ];

  return (
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
            <span className={`rounded-full border px-3 py-1 ${getRiskBadge(riskScore)}`}>{verdict}</span>
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
              Analyzed Sample
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

            <div className="mt-5 grid gap-3 sm:grid-cols-2">
              <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Verdict</p>
                <p className={`mt-2 text-lg font-semibold ${getRiskColor(riskScore)}`}>{verdict}</p>
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
              <h2 className="mt-2 text-2xl font-semibold text-white">Manifest Permissions</h2>
            </div>
            <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-xs text-slate-300">
              {mappedPermissions.length} permissions
            </span>
          </div>

          <div className="mt-6 overflow-hidden rounded-[1.5rem] border border-white/10 max-h-96 overflow-y-auto">
            <table className="min-w-full divide-y divide-white/10 text-left text-sm">
              <thead className="bg-white/[0.03] text-slate-300">
                <tr>
                  <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">Permission</th>
                  <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/10 text-slate-200">
                {mappedPermissions.map((permission: any, idx: number) => (
                  <tr key={idx} className="bg-transparent transition duration-300 hover:bg-white/[0.04]">
                    <td className="px-4 py-4 font-mono text-xs text-white sm:text-sm">{permission.name.replace('android.permission.', '')}</td>
                    <td className="px-4 py-4">
                      <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] ${getRiskBadge(permission.risk === "Green" ? 10 : 90)}`}>
                        {permission.risk}
                      </span>
                    </td>
                  </tr>
                ))}
                {mappedPermissions.length === 0 && (
                  <tr><td colSpan={2} className="px-4 py-4 text-center text-slate-400">No permissions found</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </article>

        <article className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
          <div>
            <p className="text-xs uppercase tracking-[0.28em] text-cyan-300/75">Decision Trace Summary</p>
            <h2 className="mt-2 text-2xl font-semibold text-white">Fusion Engine Output</h2>
          </div>

          <div className="mt-6 space-y-4">
            {aiSummary.map((paragraph: string, index: number) => (
              <div key={index} className="rounded-2xl border border-white/10 bg-slate-950/40 p-4">
                <div className="flex items-start gap-3">
                  <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-400 via-sky-400 to-blue-500 text-sm font-semibold text-slate-950 shadow-[0_0_18px_rgba(34,211,238,0.2)]">
                    {index + 1}
                  </div>
                  <p className="text-sm leading-6 text-slate-200">{paragraph}</p>
                </div>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.28em] text-cyan-300/75">Suspicious Indicators</p>
            <h2 className="mt-2 text-2xl font-semibold text-white">Top findings</h2>
          </div>
        </div>

        <div className="mt-6 grid gap-3">
          {suspiciousIndicators.map((indicator, idx) => {
            const Icon = indicator.icon;
            return (
              <div key={idx} className="rounded-2xl border border-white/10 bg-slate-950/40 p-4 transition duration-300 hover:-translate-y-0.5 hover:border-cyan-400/20 hover:bg-white/[0.05]">
                <div className="flex items-start gap-4">
                  <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border ${getRiskBadge(indicator.severity === "Green" ? 10 : indicator.severity === "Yellow" ? 35 : indicator.severity === "Orange" ? 60 : 90)}`}>
                    <Icon className="h-5 w-5" aria-hidden="true" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-3">
                      <h3 className="text-sm font-semibold text-white">{indicator.title}</h3>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-slate-300">{indicator.text}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

export default function AnalysisPage() {
    return (
        <AppShell>
            <Suspense fallback={
                <div className="flex h-screen items-center justify-center">
                    <LoaderCircle className="h-10 w-10 animate-spin text-cyan-400" />
                </div>
            }>
                <AnalysisContent />
            </Suspense>
        </AppShell>
    );
}