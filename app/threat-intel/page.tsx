import AppShell from "@/components/app/AppShell";
import ThreatMap from "@/components/landing/ThreatMap";

const feeds = [
  { family: "Anubis Banking", matches: 12, severity: "Critical" },
  { family: "Joker Premium", matches: 8, severity: "High" },
  { family: "SpyNote RAT", matches: 5, severity: "High" },
] as const;

export default function ThreatIntelPage() {
  return (
    <AppShell showFooter={false}>
      <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 lg:px-8">
        <p className="text-sm font-medium text-secondary">Threat Intel</p>
        <h1 className="mt-2 text-3xl font-semibold text-foreground">Global threat intelligence</h1>
        <p className="mt-2 max-w-2xl text-muted">
          Correlated malware families, C2 infrastructure, and campaign activity.
        </p>

        <div className="mt-10 grid gap-4 sm:grid-cols-3">
          {feeds.map((feed) => (
            <div
              key={feed.family}
              className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-5"
            >
              <p className="text-sm font-semibold text-foreground">{feed.family}</p>
              <p className="mt-2 text-2xl font-semibold text-foreground">{feed.matches}</p>
              <p className="mt-1 text-xs text-muted">matches this week</p>
              <span className="mt-3 inline-block rounded-full bg-red-400/10 px-2 py-0.5 text-xs text-red-300">
                {feed.severity}
              </span>
            </div>
          ))}
        </div>
      </div>

      <ThreatMap />
    </AppShell>
  );
}
