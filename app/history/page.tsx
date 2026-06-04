"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import AppShell from "@/components/app/AppShell";
import { LoaderCircle, ShieldAlert, ShieldCheck, ShieldX, TriangleAlert } from "lucide-react";

type RiskLevel = "Green" | "Yellow" | "Orange" | "Red";

function getRiskBand(score: number): RiskLevel {
  if (score < 25) return "Green";
  if (score < 50) return "Yellow";
  if (score < 75) return "Orange";
  return "Red";
}

function getRiskBadge(score: number) {
  switch (getRiskBand(score)) {
    case "Green": return "border-emerald-400/20 bg-emerald-400/10 text-emerald-200";
    case "Yellow": return "border-yellow-400/20 bg-yellow-400/10 text-yellow-200";
    case "Orange": return "border-orange-400/20 bg-orange-400/10 text-orange-200";
    case "Red": return "border-red-400/20 bg-red-400/10 text-red-200";
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

export default function HistoryPage() {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:8000/api/reports")
      .then((res) => res.json())
      .then((data) => {
        setReports(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  return (
    <AppShell>
      <div className="mx-auto max-w-6xl space-y-8 px-4 py-12 sm:px-6 lg:px-8">
        <section className="rounded-[2rem] border border-cyan-400/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-3">
              <p className="text-xs uppercase tracking-[0.34em] text-cyan-300/75">Dashboard</p>
              <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Scan History</h1>
              <p className="max-w-3xl text-sm leading-7 text-slate-300 sm:text-base">
                View all previously uploaded and analyzed APK files stored in the PostgreSQL database.
              </p>
            </div>
          </div>
        </section>

        <section className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_18px_70px_rgba(2,6,23,0.34)] backdrop-blur-xl">
          {loading ? (
             <div className="flex h-40 items-center justify-center">
                <LoaderCircle className="h-10 w-10 animate-spin text-cyan-400" />
             </div>
          ) : reports.length === 0 ? (
            <div className="flex h-40 items-center justify-center text-slate-400">
               No scans found. Upload an APK to begin.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-white/10 text-left text-sm">
                <thead className="bg-white/[0.03] text-slate-300">
                  <tr>
                    <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">APK Name</th>
                    <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">Date</th>
                    <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">Status</th>
                    <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">Verdict</th>
                    <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">Risk Score</th>
                    <th className="px-4 py-4 font-medium uppercase tracking-[0.24em]">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10 text-slate-200">
                  {reports.map((r: any) => {
                    const Icon = getRiskIcon(r.risk_score || 0);
                    return (
                      <tr key={r.id} className="bg-transparent transition duration-300 hover:bg-white/[0.04]">
                        <td className="px-4 py-4 font-medium text-white">{r.filename}</td>
                        <td className="px-4 py-4 text-slate-400">{new Date(r.created_at).toLocaleString()}</td>
                        <td className="px-4 py-4">
                            <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] ${
                                r.status === 'COMPLETED' ? 'border-emerald-400/20 bg-emerald-400/10 text-emerald-200' : 
                                r.status === 'FAILED' ? 'border-red-400/20 bg-red-400/10 text-red-200' :
                                'border-cyan-400/20 bg-cyan-400/10 text-cyan-200 animate-pulse'
                            }`}>
                                {r.status}
                            </span>
                        </td>
                        <td className="px-4 py-4">
                            {r.status === "COMPLETED" ? (
                                <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] ${getRiskBadge(r.risk_score || 0)}`}>
                                    {r.verdict}
                                </span>
                            ) : '-'}
                        </td>
                        <td className="px-4 py-4">
                            {r.status === "COMPLETED" ? (
                                <div className="flex items-center gap-2">
                                    <Icon className={`h-4 w-4 ${getRiskBadge(r.risk_score || 0).split(' ').pop()}`} />
                                    <span>{r.risk_score}/100</span>
                                </div>
                            ) : '-'}
                        </td>
                        <td className="px-4 py-4">
                            {r.status === "COMPLETED" ? (
                                <Link href={`/analysis?file=${r.id}`} className="text-cyan-400 hover:text-cyan-300 underline underline-offset-2">
                                    View Report
                                </Link>
                            ) : (
                                <span className="text-slate-500">Processing...</span>
                            )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </AppShell>
  );
}
