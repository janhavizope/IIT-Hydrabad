import Link from "next/link";
import AppShell from "@/components/app/AppShell";
import { Button } from "@/components/ui/button";

const reports = [
  { id: "RPT-2841", apk: "com.fakebank.mobile.apk", risk: 87, date: "Jun 1, 2026" },
  { id: "RPT-2839", apk: "com.noteslite.pro.apk", risk: 34, date: "May 31, 2026" },
  { id: "RPT-2835", apk: "com.flashvault.cleaner.apk", risk: 62, date: "May 30, 2026" },
] as const;

export default function ReportsPage() {
  return (
    <AppShell>
      <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-sm font-medium text-primary">Reports</p>
            <h1 className="mt-2 text-3xl font-semibold text-foreground">Security reports</h1>
            <p className="mt-2 text-muted">GenAI-generated analysis reports for completed scans.</p>
          </div>
          <Button href="/upload" variant="primary" size="sm">
            New scan
          </Button>
        </div>

        <div className="mt-10 overflow-hidden rounded-2xl border border-white/[0.08]">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/[0.08] bg-white/[0.02] text-muted">
              <tr>
                <th className="px-5 py-3 font-medium">Report ID</th>
                <th className="px-5 py-3 font-medium">APK</th>
                <th className="px-5 py-3 font-medium">Risk</th>
                <th className="px-5 py-3 font-medium">Date</th>
                <th className="px-5 py-3 font-medium" />
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {reports.map((report) => (
                <tr key={report.id} className="hover:bg-white/[0.02]">
                  <td className="px-5 py-4 font-mono text-foreground">{report.id}</td>
                  <td className="px-5 py-4 text-foreground">{report.apk}</td>
                  <td className="px-5 py-4">
                    <span className="font-semibold text-foreground">{report.risk}</span>
                    <span className="text-muted">/100</span>
                  </td>
                  <td className="px-5 py-4 text-muted">{report.date}</td>
                  <td className="px-5 py-4 text-right">
                    <Link href="/analysis" className="text-primary hover:text-primary/80">
                      View →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </AppShell>
  );
}
