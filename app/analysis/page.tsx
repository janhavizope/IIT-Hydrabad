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
  Download,
  FileText,
} from "lucide-react";
import { Button } from "@/components/ui/button";

// ─── Types ───────────────────────────────────────────────────────────────────

interface PermissionsData {
  all: string[];
  dangerous: string[];
}

interface SuspiciousIndicators {
  suspicious_apis: string[];
  hardcoded_urls: string[];
  crypto_usage: string[];
  obfuscation_signs: string[];
}

interface StaticAnalysis {
  package_name: string;
  static_risk_score: number;
  permissions: PermissionsData;
  suspicious_indicators: SuspiciousIndicators;
  summary: string[];
}

interface FinalVerdict {
  verdict: string;
  final_risk_score: number;
  confidence: number;
  reasoning: string[];
}

interface DynamicAnalysis {
  status: string;
  error?: string;
}

interface ReportData {
  final_verdict: FinalVerdict;
  static_analysis: StaticAnalysis;
  dynamic_analysis: DynamicAnalysis;
  ai_summary: string | null;
  package_name?: string;
  apk_hash?: string;
  id: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

function riskColor(score: number) {
  if (score >= 75) return "text-red-400";
  if (score >= 50) return "text-orange-400";
  if (score >= 25) return "text-yellow-400";
  return "text-green-400";
}

function riskLabel(score: number) {
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}

function verdictIcon(verdict: string) {
  const v = verdict?.toUpperCase();
  if (v === "MALWARE" || v === "MALICIOUS")
    return <ShieldX className="w-6 h-6 text-red-400" />;
  if (v === "SUSPICIOUS")
    return <ShieldAlert className="w-6 h-6 text-yellow-400" />;
  return <ShieldCheck className="w-6 h-6 text-green-400" />;
}

// ─── Download helper ──────────────────────────────────────────────────────────

function downloadReport(report: ReportData) {
  const verdict = report.final_verdict ?? {};
  const sta = report.static_analysis ?? {};
  const pkg = sta.package_name ?? report.package_name ?? "Unknown";
  const hash = report.apk_hash ?? "N/A";
  const score = verdict.final_risk_score ?? 0;
  const verdictStr = verdict.verdict ?? "Unknown";
  const confidence = verdict.confidence ?? "N/A";

  // Use ai_summary if available, otherwise build a basic text report
  let content: string;

  if (report.ai_summary) {
    content =
      `APK MALWARE ANALYSIS REPORT\n` +
      `Generated: ${new Date().toLocaleString()}\n` +
      `Report ID: ${report.id}\n` +
      `APK Hash : ${hash}\n` +
      `${"=".repeat(60)}\n\n` +
      report.ai_summary;
  } else {
    const dangerPerms = sta.permissions?.dangerous ?? [];
    const allPerms = sta.permissions?.all ?? [];
    const susApis =
      sta.suspicious_indicators?.suspicious_apis ?? [];

    content =
      `APK MALWARE ANALYSIS REPORT\n` +
      `Generated: ${new Date().toLocaleString()}\n` +
      `Report ID: ${report.id}\n` +
      `APK Hash : ${hash}\n` +
      `${"=".repeat(60)}\n\n` +
      `PACKAGE NAME\n${pkg}\n\n` +
      `VERDICT\nVerdict    : ${verdictStr}\nRisk Score : ${score}/100 — ${riskLabel(score)} RISK\nConfidence : ${confidence}\n\n` +
      `PERMISSIONS\nTotal      : ${allPerms.length}\nDangerous  : ${dangerPerms.length}\n` +
      (dangerPerms.length
        ? dangerPerms.map((p) => `  WARNING: ${p}`).join("\n") + "\n"
        : "") +
      `\nSUSPICIOUS API CALLS\n` +
      (susApis.length
        ? susApis.map((a) => `  - ${a}`).join("\n")
        : "None detected.") +
      `\n\nANALYSIS SUMMARY\n` +
      (sta.summary ?? []).join("\n");
  }

  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `malware-report-${pkg}-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── AI Summary Section ───────────────────────────────────────────────────────

function AISummarySection({ summary }: { summary: string }) {
  // Parse sections from the formatted string
  const sep = "=".repeat(60);
  const rawSections = summary.split(sep).filter((s) => s.trim());

  const sections: { title: string; body: string }[] = [];
  for (let i = 0; i < rawSections.length; i++) {
    const lines = rawSections[i].trim().split("\n");
    const title = lines[0]?.trim() ?? "";
    const body = lines.slice(1).join("\n").trim();
    if (title) sections.push({ title, body });
  }

  const colorMap: Record<string, string> = {
    "EXECUTIVE SUMMARY": "border-blue-500/40 bg-blue-950/20",
    "RISK SCORE": "border-yellow-500/40 bg-yellow-950/20",
    VERDICT: "border-green-500/40 bg-green-950/20",
    "PACKAGE INFORMATION": "border-cyan-500/40 bg-cyan-950/20",
    "SUSPICIOUS FINDINGS": "border-orange-500/40 bg-orange-950/20",
    "PERMISSION ANALYSIS SUMMARY": "border-purple-500/40 bg-purple-950/20",
    "SECURITY RECOMMENDATIONS": "border-red-500/40 bg-red-950/20",
  };

  return (
    <div className="mt-8 space-y-4">
      <div className="flex items-center gap-2 mb-4">
        <Sparkles className="w-5 h-5 text-blue-400" />
        <h2 className="text-lg font-semibold text-white">
          AI Generated Malware Analysis Report
        </h2>
        <span className="text-xs bg-blue-500/20 text-blue-300 border border-blue-500/30 px-2 py-0.5 rounded-full">
          AI GENERATED
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {sections.map(({ title, body }, idx) => {
          const isFullWidth =
            title === "EXECUTIVE SUMMARY" ||
            title === "SECURITY RECOMMENDATIONS";
          const colorClass =
            colorMap[title] ?? "border-zinc-700/40 bg-zinc-900/30";

          return (
            <div
              key={idx}
              className={`rounded-xl border p-4 ${colorClass} ${
                isFullWidth ? "md:col-span-2" : ""
              }`}
            >
              <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-3 uppercase">
                {title}
              </h3>
              <pre className="text-sm text-zinc-200 whitespace-pre-wrap font-sans leading-relaxed">
                {body}
              </pre>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

function AnalysisContent() {
  const searchParams = useSearchParams();
  const reportId = searchParams.get("report_id");

  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);

  useEffect(() => {
    if (!reportId) {
      setError("No report ID provided.");
      setLoading(false);
      return;
    }

    const fetchReport = async () => {
      try {
        const res = await fetch(
          `${API_BASE}/api/analyze-apk/${reportId}`
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        if (data.status === "PENDING") {
          setPolling(true);
          setTimeout(fetchReport, 5000);
          return;
        }

        setPolling(false);
        setReport(data);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load report.");
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [reportId]);

  if (loading || polling) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
          <div className="w-10 h-10 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-zinc-400 text-sm">
            {polling ? "Analysis in progress… checking every 5s" : "Loading report…"}
          </p>
        </div>
      </AppShell>
    );
  }

  if (error || !report) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
          <AlertTriangle className="w-10 h-10 text-red-400" />
          <p className="text-zinc-300">{error ?? "Report not found."}</p>
        </div>
      </AppShell>
    );
  }

  const verdict = report.final_verdict ?? {};
  const sta = report.static_analysis ?? {};
  const score = verdict.final_risk_score ?? 0;
  const verdictStr = verdict.verdict ?? "Unknown";
  const pkg = sta.package_name ?? report.package_name ?? "Unknown";
  const dangerPerms = sta.permissions?.dangerous ?? [];
  const allPerms = sta.permissions?.all ?? [];
  const susApis = sta.suspicious_indicators?.suspicious_apis ?? [];

  return (
    <AppShell>
      <div className="max-w-5xl mx-auto px-4 py-8 space-y-6">

        {/* Header + Download button */}
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              {verdictIcon(verdictStr)}
              <h1 className="text-2xl font-bold text-white">{pkg}</h1>
            </div>
            <p className="text-zinc-500 text-sm font-mono">{report.apk_hash}</p>
          </div>

          <Button
            onClick={() => downloadReport(report)}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white"
          >
            <Download className="w-4 h-4" />
            Download Report
          </Button>
        </div>

        {/* Risk + Verdict cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <p className="text-xs text-zinc-500 uppercase tracking-widest mb-1">Risk Score</p>
            <p className={`text-3xl font-bold ${riskColor(score)}`}>{score}/100</p>
            <p className={`text-sm mt-1 ${riskColor(score)}`}>{riskLabel(score)} RISK</p>
          </div>

          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <p className="text-xs text-zinc-500 uppercase tracking-widest mb-1">Verdict</p>
            <div className="flex items-center gap-2 mt-1">
              {verdictIcon(verdictStr)}
              <p className="text-xl font-bold text-white">{verdictStr}</p>
            </div>
            <p className="text-xs text-zinc-500 mt-2">
              Confidence: {verdict.confidence ?? "N/A"}
            </p>
          </div>

          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <p className="text-xs text-zinc-500 uppercase tracking-widest mb-1">Permissions</p>
            <p className="text-3xl font-bold text-white">{allPerms.length}</p>
            <p className="text-sm text-red-400 mt-1">{dangerPerms.length} dangerous</p>
          </div>
        </div>

        {/* Permissions */}
        {dangerPerms.length > 0 && (
          <div className="bg-zinc-900 border border-red-900/40 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <TriangleAlert className="w-4 h-4 text-red-400" />
              <h2 className="text-sm font-semibold text-red-300">Dangerous Permissions</h2>
            </div>
            <div className="flex flex-wrap gap-2">
              {dangerPerms.map((p) => (
                <span
                  key={p}
                  className="text-xs bg-red-950/40 text-red-300 border border-red-800/40 px-2 py-1 rounded-md font-mono"
                >
                  {p.replace("android.permission.", "")}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Suspicious APIs */}
        {susApis.length > 0 && (
          <div className="bg-zinc-900 border border-orange-900/40 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <ShieldAlert className="w-4 h-4 text-orange-400" />
              <h2 className="text-sm font-semibold text-orange-300">Suspicious API Calls</h2>
            </div>
            <div className="flex flex-wrap gap-2">
              {susApis.map((a) => (
                <span
                  key={a}
                  className="text-xs bg-orange-950/40 text-orange-300 border border-orange-800/40 px-2 py-1 rounded-md font-mono"
                >
                  {a}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* AI Summary */}
        {report.ai_summary ? (
          <AISummarySection summary={report.ai_summary} />
        ) : (
          <div className="flex items-center gap-2 text-zinc-500 text-sm mt-4">
            <FileText className="w-4 h-4" />
            <span>AI summary not available for this report.</span>
          </div>
        )}

      </div>
    </AppShell>
  );
}

export default function AnalysisPage() {
  return (
    <Suspense fallback={<div className="text-zinc-400 p-8">Loading…</div>}>
      <AnalysisContent />
    </Suspense>
  );
}
