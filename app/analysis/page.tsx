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
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  Legend,
} from "recharts";

// ─── Types ────────────────────────────────────────────────────────────────────

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
  signal_weights?: {
    dynamic: number;
    static: number;
    ioc: number;
  };
}

interface DynamicAnalysis {
  status: string;
  error?: string;
  behavior_risk?: {
    risk_score: number;
    risk_level: string;
  };
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

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

function riskHexColor(score: number) {
  if (score >= 75) return "#f87171";
  if (score >= 50) return "#fb923c";
  if (score >= 25) return "#facc15";
  return "#4ade80";
}

function downloadReport(report: ReportData) {
  const verdict = report.final_verdict ?? {};
  const sta = report.static_analysis ?? {};
  const pkg = sta.package_name ?? report.package_name ?? "Unknown";
  const hash = report.apk_hash ?? "N/A";
  const score = verdict.final_risk_score ?? 0;
  const verdictStr = verdict.verdict ?? "Unknown";
  const confidence = verdict.confidence ?? "N/A";
  const dangerPerms = sta.permissions?.dangerous ?? [];
  const allPerms = sta.permissions?.all ?? [];
  const susApis = sta.suspicious_indicators?.suspicious_apis ?? [];
  const urls = sta.suspicious_indicators?.hardcoded_urls ?? [];
  const cryptoUsage = sta.suspicious_indicators?.crypto_usage ?? [];
  const weights = verdict.signal_weights;
  const scoreColor = riskHexColor(score);
  const riskLbl = riskLabel(score);
  const generated = new Date().toLocaleString();

  // Parse AI summary sections
  const sep60 = "=".repeat(60);
  let aiSectionsHtml = "";
  if (report.ai_summary) {
    const rawSections = report.ai_summary.split(sep60).filter((s) => s.trim());
    const colorMap: Record<string, string> = {
      "EXECUTIVE SUMMARY": "#1e3a5f",
      "RISK SCORE": "#3b2f00",
      "VERDICT": "#0f2e1a",
      "PACKAGE INFORMATION": "#0d2e35",
      "SUSPICIOUS FINDINGS": "#3b1f00",
      "PERMISSION ANALYSIS SUMMARY": "#2a1a3e",
      "SECURITY RECOMMENDATIONS": "#3b1a1a",
    };
    const borderMap: Record<string, string> = {
      "EXECUTIVE SUMMARY": "#3b82f6",
      "RISK SCORE": "#eab308",
      "VERDICT": "#22c55e",
      "PACKAGE INFORMATION": "#06b6d4",
      "SUSPICIOUS FINDINGS": "#f97316",
      "PERMISSION ANALYSIS SUMMARY": "#a855f7",
      "SECURITY RECOMMENDATIONS": "#ef4444",
    };
    for (const raw of rawSections) {
      const lines = raw.trim().split("\n");
      const title = lines[0]?.trim() ?? "";
      const body = lines.slice(1).join("\n").trim();
      if (!title) continue;
      const bg = colorMap[title] ?? "#1c1c1e";
      const border = borderMap[title] ?? "#3f3f46";
      const fullWidth = title === "EXECUTIVE SUMMARY" || title === "SECURITY RECOMMENDATIONS";
      aiSectionsHtml += `
        <div style="background:${bg};border:1px solid ${border};border-radius:10px;padding:16px;${fullWidth ? "grid-column:1/-1;" : ""}">
          <div style="font-size:10px;font-weight:700;letter-spacing:2px;color:#9ca3af;margin-bottom:10px;">${title}</div>
          <pre style="font-family:'Courier New',monospace;font-size:12px;color:#e4e4e7;white-space:pre-wrap;margin:0;line-height:1.7;">${body}</pre>
        </div>`;
    }
  }

  // Permission rows
  const permRowsHtml = allPerms.map((p) => {
    const isDanger = dangerPerms.includes(p);
    const shortName = p.replace("android.permission.", "").replace("org.fdroid.fdroid.", "");
    return `<tr>
      <td style="padding:6px 10px;font-size:11px;color:${isDanger ? "#fca5a5" : "#a1a1aa"};font-family:'Courier New',monospace;">${shortName}</td>
      <td style="padding:6px 10px;text-align:right;">
        <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:${isDanger ? "#3b1a1a" : "#1a2e1a"};color:${isDanger ? "#f87171" : "#4ade80"};">
          ${isDanger ? "DANGEROUS" : "NORMAL"}
        </span>
      </td>
    </tr>`;
  }).join("");

  // Signal weights bar
  const staticPct = weights ? Math.round(weights.static * 100) : 100;
  const dynamicPct = weights ? Math.round(weights.dynamic * 100) : 0;
  const iocPct = weights ? Math.round(weights.ioc * 100) : 0;

  // Pie chart SVG (simple donut)
  const total = allPerms.length || 1;
  const dangerPct = (dangerPerms.length / total) * 100;
  const normalPct = 100 - dangerPct;
  const r = 40;
  const circ = 2 * Math.PI * r;
  const dangerDash = (dangerPct / 100) * circ;
  const normalDash = circ - dangerDash;
  const pieSvg = `<svg width="100" height="100" viewBox="0 0 100 100">
    <circle cx="50" cy="50" r="${r}" fill="none" stroke="#4ade80" stroke-width="16" stroke-dasharray="${circ}" stroke-dashoffset="0" transform="rotate(-90 50 50)"/>
    <circle cx="50" cy="50" r="${r}" fill="none" stroke="#f87171" stroke-width="16" stroke-dasharray="${dangerDash} ${normalDash}" stroke-dashoffset="0" transform="rotate(-90 50 50)"/>
    <text x="50" y="46" text-anchor="middle" fill="#e4e4e7" font-size="14" font-weight="bold" font-family="monospace">${allPerms.length}</text>
    <text x="50" y="60" text-anchor="middle" fill="#9ca3af" font-size="8" font-family="monospace">PERMS</text>
  </svg>`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>NexEdge Report — ${pkg}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', system-ui, sans-serif; padding: 32px 24px; }
  .page { max-width: 900px; margin: 0 auto; }
  h2 { font-size: 11px; letter-spacing: 2px; color: #6b7280; margin-bottom: 14px; font-weight: 600; }
  pre { font-family: 'Courier New', monospace; }
  @media print { body { background: #0d1117 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
</style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid #21262d;padding-bottom:20px;margin-bottom:24px;">
    <div style="display:flex;align-items:center;gap:12px;">
      <div style="width:42px;height:42px;background:#00e5ff;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:18px;color:#0d1117;">N</div>
      <div>
        <div style="font-size:18px;font-weight:700;letter-spacing:1px;color:#e6edf3;">NexEdge</div>
        <div style="font-size:10px;letter-spacing:3px;color:#6b7280;">MALWARE INTELLIGENCE PLATFORM</div>
      </div>
    </div>
    <div style="text-align:right;font-size:11px;color:#6b7280;line-height:2;">
      <div>Report ID: ${report.id}</div>
      <div>Generated: ${generated}</div>
    </div>
  </div>

  <!-- PACKAGE BAR -->
  <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px 22px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">
    <div>
      <div style="font-size:16px;font-weight:700;color:#00e5ff;">${pkg}</div>
      <div style="font-size:10px;color:#6b7280;margin-top:4px;font-family:'Courier New',monospace;word-break:break-all;">${hash}</div>
    </div>
    <div style="display:flex;align-items:center;gap:16px;">
      <div style="background:${verdictStr.toUpperCase() === "SAFE" ? "#0f2e1a" : "#3b1a1a"};border:1px solid ${verdictStr.toUpperCase() === "SAFE" ? "#22c55e" : "#ef4444"};border-radius:20px;padding:5px 16px;font-size:12px;color:${verdictStr.toUpperCase() === "SAFE" ? "#4ade80" : "#f87171"};font-weight:700;letter-spacing:1px;">
        ${verdictStr.toUpperCase() === "SAFE" ? "✓" : "✗"} ${verdictStr.toUpperCase()}
      </div>
      <div style="width:68px;height:68px;border-radius:50%;border:3px solid ${scoreColor};display:flex;flex-direction:column;align-items:center;justify-content:center;">
        <div style="font-size:20px;font-weight:700;color:${scoreColor};line-height:1;">${score}</div>
        <div style="font-size:9px;color:#6b7280;">/100</div>
      </div>
    </div>
  </div>

  <!-- METRIC CARDS -->
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px;">
    <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px;">
      <div style="font-size:9px;letter-spacing:2px;color:#6b7280;margin-bottom:6px;">RISK LEVEL</div>
      <div style="font-size:22px;font-weight:700;color:${scoreColor};">${riskLbl}</div>
      <div style="font-size:11px;color:#6b7280;margin-top:2px;">${score}/100</div>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px;">
      <div style="font-size:9px;letter-spacing:2px;color:#6b7280;margin-bottom:6px;">CONFIDENCE</div>
      <div style="font-size:22px;font-weight:700;color:#e3b341;">${confidence}</div>
      <div style="font-size:11px;color:#6b7280;margin-top:2px;">Analysis confidence</div>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px;">
      <div style="font-size:9px;letter-spacing:2px;color:#6b7280;margin-bottom:6px;">PERMISSIONS</div>
      <div style="font-size:22px;font-weight:700;color:#e6edf3;">${allPerms.length}</div>
      <div style="font-size:11px;color:#f87171;margin-top:2px;">${dangerPerms.length} dangerous</div>
    </div>
  </div>

  <!-- RISK SCORE BAR -->
  <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:20px;">
    <h2>RISK SCORE GAUGE</h2>
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
      <div style="text-align:center;min-width:80px;">
        <div style="font-size:42px;font-weight:700;color:${scoreColor};line-height:1;">${score}</div>
        <div style="font-size:11px;color:#6b7280;">/100 — ${riskLbl}</div>
      </div>
      <div style="flex:1;min-width:200px;">
        <div style="background:#27272a;border-radius:99px;height:12px;overflow:hidden;margin-bottom:6px;">
          <div style="height:12px;border-radius:99px;width:${score}%;background:${scoreColor};transition:width 0.5s;"></div>
        </div>
        <div style="display:flex;justify-content:space-between;font-size:10px;">
          <span style="color:#4ade80;">LOW</span>
          <span style="color:#facc15;">MEDIUM</span>
          <span style="color:#fb923c;">HIGH</span>
          <span style="color:#f87171;">CRITICAL</span>
        </div>
      </div>
    </div>
  </div>

  <!-- CHARTS ROW: PIE + SIGNAL WEIGHTS -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px;">

    <!-- Permission Pie -->
    <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;">
      <h2>PERMISSION BREAKDOWN</h2>
      <div style="display:flex;align-items:center;gap:20px;">
        ${pieSvg}
        <div style="font-size:12px;line-height:2;">
          <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#4ade80;margin-right:6px;"></span><span style="color:#a1a1aa;">Normal: ${allPerms.length - dangerPerms.length}</span></div>
          <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#f87171;margin-right:6px;"></span><span style="color:#a1a1aa;">Dangerous: ${dangerPerms.length}</span></div>
          <div style="margin-top:6px;font-size:11px;color:#6b7280;">Total: ${allPerms.length} permissions</div>
        </div>
      </div>
    </div>

    <!-- Signal Weights -->
    <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;">
      <h2>SIGNAL WEIGHTS</h2>
      <div style="space-y:10px;">
        ${[
          { label: "Static Analysis", value: staticPct, color: "#38bdf8" },
          { label: "Dynamic Analysis", value: dynamicPct, color: "#a78bfa" },
          { label: "IOC Score", value: iocPct, color: "#f97316" },
        ].map(({ label, value, color }) => `
          <div style="margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;font-size:11px;color:#a1a1aa;margin-bottom:4px;">
              <span>${label}</span><span style="color:${color};font-weight:600;">${value}%</span>
            </div>
            <div style="background:#27272a;border-radius:99px;height:8px;overflow:hidden;">
              <div style="height:8px;border-radius:99px;width:${value}%;background:${color};"></div>
            </div>
          </div>`).join("")}
      </div>
    </div>
  </div>

  <!-- THREAT INDICATORS BAR CHART (inline SVG bars) -->
  <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:20px;">
    <h2>THREAT INDICATORS</h2>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;text-align:center;">
      ${[
        { label: "Suspicious APIs", count: susApis.length },
        { label: "Hardcoded URLs", count: urls.length },
        { label: "Crypto Usage", count: cryptoUsage.length },
        { label: "Obfuscation", count: sta.suspicious_indicators?.obfuscation_signs?.length ?? 0 },
      ].map(({ label, count }) => `
        <div>
          <div style="font-size:24px;font-weight:700;color:${count > 0 ? "#f97316" : "#4ade80"};">${count}</div>
          <div style="font-size:10px;color:#6b7280;margin-top:4px;">${label}</div>
          <div style="height:4px;border-radius:99px;background:${count > 0 ? "#f97316" : "#4ade80"};margin-top:6px;opacity:0.6;"></div>
        </div>`).join("")}
    </div>
  </div>

  ${aiSectionsHtml ? `
  <!-- AI SUMMARY SECTIONS -->
  <div style="border:1px solid #1d4ed8;border-radius:10px;padding:16px;margin-bottom:20px;background:#0f172a;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px;">
      <div style="font-size:13px;font-weight:600;color:#93c5fd;">✦ AI Generated Malware Analysis Report</div>
      <span style="font-size:10px;background:#1e3a5f;color:#60a5fa;border:1px solid #2563eb;padding:2px 8px;border-radius:99px;">AI GENERATED</span>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      ${aiSectionsHtml}
    </div>
  </div>` : ""}

  <!-- PERMISSIONS TABLE -->
  <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:20px;">
    <h2>ALL PERMISSIONS (${allPerms.length})</h2>
    <table style="width:100%;border-collapse:collapse;">
      <thead>
        <tr style="border-bottom:1px solid #21262d;">
          <th style="text-align:left;padding:6px 10px;font-size:10px;color:#6b7280;font-weight:600;letter-spacing:1px;">PERMISSION</th>
          <th style="text-align:right;padding:6px 10px;font-size:10px;color:#6b7280;font-weight:600;letter-spacing:1px;">STATUS</th>
        </tr>
      </thead>
      <tbody>${permRowsHtml}</tbody>
    </table>
  </div>

  <!-- FOOTER -->
  <div style="border-top:1px solid #21262d;padding-top:14px;display:flex;justify-content:space-between;font-size:10px;color:#4b5563;">
    <span>NexEdge Malware Intelligence Platform — Confidential</span>
    <span>Generated by AI Engine · ${generated}</span>
  </div>

</div>
</body>
</html>`;

  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `nexedge-report-${pkg}-${Date.now()}.html`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Charts Section ───────────────────────────────────────────────────────────

function ChartsSection({ report }: { report: ReportData }) {
  const sta = report.static_analysis ?? {};
  const verdict = report.final_verdict ?? {};
  const allPerms = sta.permissions?.all ?? [];
  const dangerPerms = sta.permissions?.dangerous ?? [];
  const normalPerms = allPerms.length - dangerPerms.length;
  const indicators = sta.suspicious_indicators ?? {};
  const weights = verdict.signal_weights;

  // Pie chart: permission breakdown
  const permPieData = [
    { name: "Dangerous", value: dangerPerms.length },
    { name: "Normal", value: normalPerms },
  ];
  const PIE_COLORS = ["#f87171", "#4ade80"];

  // Bar chart: threat indicators count
  const threatBarData = [
    { name: "Suspicious APIs", count: indicators.suspicious_apis?.length ?? 0 },
    { name: "Hardcoded URLs", count: indicators.hardcoded_urls?.length ?? 0 },
    { name: "Crypto Usage", count: indicators.crypto_usage?.length ?? 0 },
    { name: "Obfuscation", count: indicators.obfuscation_signs?.length ?? 0 },
  ];

  // Radar chart: signal weights
  const radarData = weights
    ? [
        { subject: "Static", value: Math.round(weights.static * 100) },
        { subject: "Dynamic", value: Math.round(weights.dynamic * 100) },
        { subject: "IOC", value: Math.round(weights.ioc * 100) },
        { subject: "Permission Risk", value: dangerPerms.length > 0 ? Math.min(dangerPerms.length * 10, 100) : 0 },
        { subject: "Threat Indicators", value: Math.min((indicators.suspicious_apis?.length ?? 0) * 20, 100) },
      ]
    : null;

  // Risk score bar
  const score = verdict.final_risk_score ?? 0;
  const scoreBarData = [
    { name: "Risk Score", value: score, fill: score >= 75 ? "#f87171" : score >= 50 ? "#fb923c" : score >= 25 ? "#facc15" : "#4ade80" },
    { name: "Safe Zone", value: 100 - score, fill: "#27272a" },
  ];

  const tooltipStyle = {
    backgroundColor: "#18181b",
    border: "1px solid #3f3f46",
    borderRadius: "8px",
    color: "#e4e4e7",
    fontSize: "12px",
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 mb-2">
        <Fingerprint className="w-5 h-5 text-cyan-400" />
        <h2 className="text-lg font-semibold text-white">Threat Analysis Charts</h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

        {/* Permission Breakdown Pie */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <p className="text-xs text-zinc-500 uppercase tracking-widest mb-4">Permission Breakdown</p>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={permPieData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={4}
                dataKey="value"
                label={({ name, value }) => `${name}: ${value}`}
                labelLine={false}
              >
                {permPieData.map((_, i) => (
                  <Cell key={i} fill={PIE_COLORS[i]} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
              <Legend
                formatter={(value) => (
                  <span style={{ color: "#a1a1aa", fontSize: "12px" }}>{value}</span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
          <p className="text-center text-xs text-zinc-500 mt-1">
            {allPerms.length} total &nbsp;·&nbsp;{" "}
            <span className="text-red-400">{dangerPerms.length} dangerous</span>
          </p>
        </div>

        {/* Threat Indicators Bar */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <p className="text-xs text-zinc-500 uppercase tracking-widest mb-4">Threat Indicators</p>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={threatBarData} barSize={28}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
              <XAxis
                dataKey="name"
                tick={{ fill: "#71717a", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "#71717a", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#27272a" }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {threatBarData.map((entry, i) => (
                  <Cell
                    key={i}
                    fill={entry.count > 0 ? "#f97316" : "#3f3f46"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Risk Score Gauge Bar */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <p className="text-xs text-zinc-500 uppercase tracking-widest mb-4">Risk Score Breakdown</p>
          <div className="flex items-center justify-center mb-4">
            <div className="text-center">
              <p className={`text-5xl font-bold ${riskColor(score)}`}>{score}</p>
              <p className="text-zinc-500 text-sm">/100</p>
              <p className={`text-sm font-semibold mt-1 ${riskColor(score)}`}>{riskLabel(score)} RISK</p>
            </div>
          </div>
          <div className="w-full bg-zinc-800 rounded-full h-3 overflow-hidden">
            <div
              className="h-3 rounded-full transition-all duration-700"
              style={{
                width: `${score}%`,
                backgroundColor:
                  score >= 75 ? "#f87171" : score >= 50 ? "#fb923c" : score >= 25 ? "#facc15" : "#4ade80",
              }}
            />
          </div>
          <div className="flex justify-between text-xs text-zinc-600 mt-1">
            <span>0</span>
            <span>25</span>
            <span>50</span>
            <span>75</span>
            <span>100</span>
          </div>
          <div className="flex justify-between text-xs mt-1">
            <span className="text-green-500">LOW</span>
            <span className="text-yellow-500">MED</span>
            <span className="text-orange-500">HIGH</span>
            <span className="text-red-500">CRIT</span>
          </div>
        </div>

        {/* Radar Chart: Signal Weights or Static Analysis Breakdown */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <p className="text-xs text-zinc-500 uppercase tracking-widest mb-4">
            {radarData ? "Signal Analysis" : "Static Analysis Breakdown"}
          </p>
          {radarData ? (
            <ResponsiveContainer width="100%" height={220}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="#3f3f46" />
                <PolarAngleAxis
                  dataKey="subject"
                  tick={{ fill: "#71717a", fontSize: 10 }}
                />
                <Radar
                  name="Score"
                  dataKey="value"
                  stroke="#38bdf8"
                  fill="#38bdf8"
                  fillOpacity={0.25}
                />
                <Tooltip contentStyle={tooltipStyle} />
              </RadarChart>
            </ResponsiveContainer>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart
                data={[
                  { name: "Static Risk", value: sta.static_risk_score ?? 0 },
                  { name: "Danger Perms", value: dangerPerms.length * 10 },
                  { name: "All Perms", value: Math.min(allPerms.length, 100) },
                ]}
                barSize={32}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                <XAxis dataKey="name" tick={{ fill: "#71717a", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#71717a", fontSize: 10 }} axisLine={false} tickLine={false} domain={[0, 100]} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#27272a" }} />
                <Bar dataKey="value" fill="#818cf8" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

      </div>
    </div>
  );
}

// ─── AI Summary Section ───────────────────────────────────────────────────────

function AISummarySection({ summary }: { summary: string }) {
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
            title === "EXECUTIVE SUMMARY" || title === "SECURITY RECOMMENDATIONS";
          const colorClass = colorMap[title] ?? "border-zinc-700/40 bg-zinc-900/30";

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
        const res = await fetch(`${API_BASE}/api/analyze-apk/${reportId}`);
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

        {/* Header + Download */}
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

        {/* Risk + Verdict + Permissions summary cards */}
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
            <p className="text-xs text-zinc-500 mt-2">Confidence: {verdict.confidence ?? "N/A"}</p>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <p className="text-xs text-zinc-500 uppercase tracking-widest mb-1">Permissions</p>
            <p className="text-3xl font-bold text-white">{allPerms.length}</p>
            <p className="text-sm text-red-400 mt-1">{dangerPerms.length} dangerous</p>
          </div>
        </div>

        {/* ── CHARTS ── */}
        <ChartsSection report={report} />

        {/* Dangerous Permissions */}
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