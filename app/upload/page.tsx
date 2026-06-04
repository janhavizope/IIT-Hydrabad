import APKUpload from "@/components/ui/APKUpload";
import AppShell from "@/components/app/AppShell";

export default function UploadPage() {
  return (
    <AppShell>
      <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6 lg:px-8">
        <p className="text-sm font-medium text-primary">Upload</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-foreground">
          Analyze an APK
        </h1>
        <p className="mt-3 max-w-2xl text-muted">
          Submit an Android package for AI reverse engineering, static and dynamic analysis, and
          automated risk scoring.
        </p>

        <div className="mt-10">
          <APKUpload />
        </div>

        <div className="mt-8 rounded-2xl border border-white/[0.08] bg-white/[0.02] p-5">
          <p className="text-sm font-medium text-foreground">Pipeline</p>
          <ul className="mt-3 space-y-2 text-sm text-muted">
            <li>• Files are isolated before analysis begins</li>
            <li>• Static + dynamic signals feed the risk model</li>
            <li>• GenAI generates an analyst-ready report on completion</li>
          </ul>
        </div>
      </div>
    </AppShell>
  );
}
