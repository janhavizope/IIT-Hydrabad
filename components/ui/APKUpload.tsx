"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  CheckCircle2,
  LoaderCircle,
  Package,
  ShieldCheck,
  Sparkles,
  UploadCloud,
} from "lucide-react";
import { Button } from "@/components/ui/button";

// ─── Types ────────────────────────────────────────────────────────────────────

type UploadState = "idle" | "uploading" | "analyzing" | "success" | "error";

interface AnalysisStep {
  id: string;
  label: string;
  status: "waiting" | "active" | "done";
}

// ─── Analysis steps shown during polling ─────────────────────────────────────

const INITIAL_STEPS: AnalysisStep[] = [
  { id: "upload",      label: "APK Uploaded Successfully",       status: "waiting" },
  { id: "static",      label: "Running Static Analysis",         status: "waiting" },
  { id: "permissions", label: "Checking Permissions",            status: "waiting" },
  { id: "apis",        label: "Scanning for Suspicious APIs",    status: "waiting" },
  { id: "dynamic",     label: "Running Dynamic Analysis",        status: "waiting" },
  { id: "risk",        label: "Calculating Risk Score",          status: "waiting" },
  { id: "ai",          label: "Generating AI Report",            status: "waiting" },
  { id: "done",        label: "Analysis Complete!",              status: "waiting" },
];

// How long (ms) each step stays "active" before moving to next during polling
const STEP_INTERVAL = 18_000; // ~18s per step so all 7 steps fill ~2 min gracefully

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ─── Helpers ─────────────────────────────────────────────────────────────────

const formatFileSize = (size: number | null) => {
  if (size === null) return "—";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
};

// ─── Step Row ─────────────────────────────────────────────────────────────────

function StepRow({ step }: { step: AnalysisStep }) {
  return (
    <div className="flex items-center gap-3">
      {step.status === "done" ? (
        <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" />
      ) : step.status === "active" ? (
        <LoaderCircle className="h-5 w-5 shrink-0 animate-spin text-primary" />
      ) : (
        <div className="h-5 w-5 shrink-0 rounded-full border border-white/20" />
      )}
      <span
        className={`text-sm font-medium transition-colors duration-300 ${
          step.status === "done"
            ? "text-emerald-300"
            : step.status === "active"
            ? "text-white"
            : "text-slate-500"
        }`}
      >
        {step.label}
      </span>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function APKUpload() {
  const router = useRouter();

  // Upload state
  const [fileName, setFileName]   = useState<string | null>(null);
  const [fileSize, setFileSize]   = useState<number | null>(null);
  const [progress, setProgress]   = useState(0);
  const [state, setState]         = useState<UploadState>("idle");
  const [message, setMessage]     = useState("Drop an APK file here or select one to begin.");
  const [isDragging, setIsDragging] = useState(false);

  // Analysis progress state
  const [steps, setSteps]           = useState<AnalysisStep[]>(INITIAL_STEPS);
  const [activeStepIdx, setActiveStepIdx] = useState(0);
  const [reportId, setReportId]     = useState<string | null>(null);

  const inputRef    = useRef<HTMLInputElement>(null);
  const stepTimer   = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollTimer   = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Cleanup on unmount ──
  useEffect(() => {
    return () => {
      if (stepTimer.current) clearInterval(stepTimer.current);
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, []);

  // ── Step auto-advance while polling ──
  const startStepAnimation = () => {
    let idx = 0;

    // Mark first step done immediately (upload succeeded)
    setSteps((prev) =>
      prev.map((s, i) =>
        i === 0 ? { ...s, status: "done" } : i === 1 ? { ...s, status: "active" } : s
      )
    );
    idx = 1;
    setActiveStepIdx(1);

    stepTimer.current = setInterval(() => {
      idx += 1;
      // Stop auto-advance at "Generating AI Report" (index 6) — let poll finish it
      if (idx >= INITIAL_STEPS.length - 1) {
        if (stepTimer.current) clearInterval(stepTimer.current);
        return;
      }
      setActiveStepIdx(idx);
      setSteps((prev) =>
        prev.map((s, i) => {
          if (i < idx)  return { ...s, status: "done" };
          if (i === idx) return { ...s, status: "active" };
          return { ...s, status: "waiting" };
        })
      );
    }, STEP_INTERVAL);
  };

  // ── Mark all steps done and redirect ──
  const finishSteps = (id: string) => {
    if (stepTimer.current) clearInterval(stepTimer.current);
    if (pollTimer.current) clearInterval(pollTimer.current);

    setSteps((prev) => prev.map((s) => ({ ...s, status: "done" })));
    setState("success");
    setMessage("Analysis complete! Redirecting to report...");

    setTimeout(() => router.push(`/analysis?report_id=${id}`), 1200);
  };

  // ── Poll backend for completion ──
  const startPolling = (id: string) => {
    pollTimer.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/analyze-apk/${id}`);
        if (!res.ok) return;
        const data = await res.json();
        if (data.status !== "PENDING") {
          finishSteps(id);
        }
      } catch {
        // network hiccup — keep polling
      }
    }, 5000);
  };

  // ── File validation ──
  const validateFile = (file: File | null) => {
    if (!file) return { valid: false, reason: "No file selected." };
    if (!file.name.toLowerCase().endsWith(".apk"))
      return { valid: false, reason: "Only .apk files are allowed." };
    return { valid: true, reason: "" };
  };

  // ── Upload ──
  const startUpload = (file: File) => {
    const validation = validateFile(file);
    if (!validation.valid) {
      setState("error");
      setProgress(0);
      setFileName(null);
      setFileSize(null);
      setMessage(validation.reason);
      return;
    }

    setFileName(file.name);
    setFileSize(file.size);
    setState("uploading");
    setProgress(0);
    setMessage(`Uploading ${file.name}...`);
    setSteps(INITIAL_STEPS);

    const xhr = new XMLHttpRequest();
    const formData = new FormData();
    formData.append("file", file);

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        setProgress(Math.min(Math.round((event.loaded / event.total) * 100), 90));
      }
    };

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const response = JSON.parse(xhr.responseText);
          const id: string = response.report_id;
          setReportId(id);
          setProgress(100);
          setState("analyzing");
          setMessage("APK received. Analysis pipeline running...");
          startStepAnimation();
          startPolling(id);
        } catch {
          setState("error");
          setMessage("Failed to parse server response.");
        }
      } else {
        setState("error");
        setProgress(0);
        try {
          const errResponse = JSON.parse(xhr.responseText);
          setMessage(`Upload failed: ${errResponse.detail || xhr.statusText}`);
        } catch {
          setMessage(`Upload failed with status: ${xhr.status}`);
        }
      }
    };

    xhr.onerror = () => {
      setState("error");
      setProgress(0);
      setMessage("Network error occurred during upload.");
    };

    xhr.open("POST", `${API_BASE}/api/upload-apk`, true);
    xhr.send(formData);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0] ?? null;
    if (f) startUpload(f);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const f = e.dataTransfer.files?.[0] ?? null;
    if (f) startUpload(f);
  };

  // ── Status badge config ──
  const statusConfig = {
    idle:      { label: "Awaiting APK",     icon: UploadCloud,   tone: "border-primary/20 bg-primary/10 text-primary" },
    uploading: { label: "Uploading",         icon: LoaderCircle,  tone: "border-amber-400/20 bg-amber-400/10 text-amber-200" },
    analyzing: { label: "Analyzing",         icon: LoaderCircle,  tone: "border-blue-400/20 bg-blue-400/10 text-blue-200" },
    success:   { label: "Analysis queued",   icon: ShieldCheck,   tone: "border-emerald-400/20 bg-emerald-400/10 text-emerald-200" },
    error:     { label: "Blocked",           icon: AlertTriangle, tone: "border-red-400/20 bg-red-400/10 text-red-200" },
  }[state];

  const StatusIcon = statusConfig.icon;
  const isAnalyzing = state === "analyzing";

  // ─────────────────────────────────────────────────────────────────────────────
  // If analysis is running, show the full-screen progress view
  // ─────────────────────────────────────────────────────────────────────────────
  if (isAnalyzing || state === "success") {
    return (
      <div className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-6">
        <div className="flex items-center gap-3 mb-6">
          <Sparkles className="h-5 w-5 text-primary" />
          <h2 className="text-xl font-semibold text-white">Analysis in Progress</h2>
        </div>

        {/* File info */}
        <div className="mb-6 flex items-center gap-3 rounded-xl border border-white/10 bg-slate-950/40 px-4 py-3">
          <Package className="h-5 w-5 text-primary shrink-0" />
          <div>
            <p className="text-sm font-medium text-white">{fileName}</p>
            <p className="text-xs text-slate-400">{formatFileSize(fileSize)}</p>
          </div>
        </div>

        {/* Steps */}
        <div className="rounded-2xl border border-white/10 bg-slate-950/40 p-5 space-y-4">
          {steps.map((step) => (
            <StepRow key={step.id} step={step} />
          ))}
        </div>

        {/* Status message */}
        <div className={`mt-5 rounded-2xl border p-4 ${statusConfig.tone}`}>
          <div className="flex items-center gap-2">
            <StatusIcon
              className={`h-4 w-4 ${state === "analyzing" ? "animate-spin" : ""}`}
            />
            <p className="text-sm font-medium text-white">{message}</p>
          </div>
        </div>

        <p className="mt-4 text-xs text-slate-500 text-center">
          This may take a few minutes. Please keep this page open.
        </p>
      </div>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Default upload UI (unchanged from original)
  // ─────────────────────────────────────────────────────────────────────────────
  return (
    <div className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.28em] text-muted">APK Upload</p>
          <h2 className="mt-2 text-2xl font-semibold text-foreground">Drop sample for analysis</h2>
        </div>
        <span className="rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-primary">
          .apk only
        </span>
      </div>

      <div
        onDrop={handleDrop}
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        className={`mt-5 rounded-2xl border-2 border-dashed p-5 transition duration-300 ${
          isDragging
            ? "border-primary bg-primary/10 shadow-[0_0_30px_rgba(0,229,168,0.15)]"
            : "border-white/10 bg-background/50 hover:border-primary/30 hover:bg-white/[0.03]"
        }`}
      >
        <div className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="rounded-[1.5rem] border border-white/10 bg-slate-950/40 p-5">
            <div className="flex items-start gap-4">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-primary/20 bg-primary/10 text-primary">
                <Package className="h-7 w-7" />
              </div>
              <div className="min-w-0 flex-1 space-y-4">
                <div>
                  <p className="text-lg font-semibold text-white">Drag and drop your APK file</p>
                  <p className="mt-2 text-sm leading-6 text-slate-300">
                    Uploaded samples are routed through static analysis, risk scoring, and AI-powered threat assessment.
                  </p>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Filename</p>
                    <p className="mt-2 break-all text-sm font-medium text-white">{fileName ?? "No file selected"}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-xs uppercase tracking-[0.24em] text-slate-400">File Size</p>
                    <p className="mt-2 text-sm font-medium text-white">{formatFileSize(fileSize)}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Upload Status</p>
                    <div className="mt-2 flex items-center gap-2">
                      <StatusIcon className={`h-4 w-4 ${state === "uploading" ? "animate-spin" : ""}`} />
                      <p className="text-sm font-medium text-white">{statusConfig.label}</p>
                    </div>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Scan Progress</p>
                    <p className="mt-2 text-sm font-medium text-white">{progress}%</p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <Button type="button" variant="primary" onClick={() => inputRef.current?.click()}>
                    Select APK
                  </Button>
                  <span className="text-sm text-slate-400">or drop a file into the zone</span>
                </div>
                <input ref={inputRef} type="file" accept=".apk" onChange={handleFileChange} className="hidden" />
              </div>
            </div>
          </div>

          <div className="rounded-[1.5rem] border border-white/10 bg-slate-950/40 p-5">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Upload progress</span>
              <span className="font-medium text-white">{progress}%</span>
            </div>
            <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/5">
              <div
                className={`h-full rounded-full transition-all duration-300 ${
                  state === "success" ? "bg-emerald-400" : state === "error" ? "bg-red-400" : "bg-gradient-to-r from-primary via-secondary to-accent"
                }`}
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className={`mt-5 rounded-2xl border p-4 ${statusConfig.tone}`}>
              <p className="text-xs uppercase tracking-[0.24em] text-white/70">Upload Status</p>
              <p className="mt-2 text-sm font-medium text-white">{message}</p>
              <div className="mt-4 flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-white/70">
                <StatusIcon className={`h-4 w-4 ${state === "uploading" ? "animate-spin" : ""}`} />
                <span>{statusConfig.label}</span>
              </div>
            </div>
            <div className="mt-5 rounded-2xl border border-white/10 bg-white/[0.03] p-4">
              <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Security posture</p>
              <p className="mt-2 text-sm leading-6 text-slate-300">
                APK uploads are isolated for inspection and evaluated against signature checks, permission abuse, and post-install indicators.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
