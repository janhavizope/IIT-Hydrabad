import AppShell from "@/components/app/AppShell";

const sections = [
  {
    id: "getting-started",
    title: "Getting started",
    body: "Upload an APK via the dashboard or API. APKThreatIQ runs reverse engineering, static and dynamic analysis, then returns a risk score and GenAI report.",
  },
  {
    id: "api",
    title: "API",
    body: "REST API endpoints for upload, scan status, and report retrieval. Authentication via API keys (demo mode available for hackathon builds).",
  },
  {
    id: "privacy",
    title: "Privacy",
    body: "Uploaded samples are processed in isolated sandboxes. Data retention policies apply per your organization tier.",
  },
] as const;

export default function DocsPage() {
  return (
    <AppShell>
      <div className="mx-auto max-w-3xl px-4 py-12 sm:px-6 lg:px-8">
        <p className="text-sm font-medium text-primary">Documentation</p>
        <h1 className="mt-2 text-3xl font-semibold text-foreground">APKThreatIQ docs</h1>
        <p className="mt-4 text-muted">Integration guides and platform reference.</p>

        <div className="mt-12 space-y-10">
          {sections.map((section) => (
            <section key={section.id} id={section.id} className="scroll-mt-24">
              <h2 className="text-xl font-semibold text-foreground">{section.title}</h2>
              <p className="mt-3 leading-relaxed text-muted">{section.body}</p>
            </section>
          ))}
        </div>
      </div>
    </AppShell>
  );
}
