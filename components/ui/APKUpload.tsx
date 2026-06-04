"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, LoaderCircle, Package, ShieldCheck, UploadCloud } from "lucide-react";
import { Button } from "@/components/ui/button";

type UploadState = "idle" | "uploading" | "success" | "error";

export default function APKUpload() {
  const router = useRouter();
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileSize, setFileSize] = useState<number | null>(null);
  const [progress, setProgress] = useState(0);
  const [state, setState] = useState<UploadState>("idle");
  const [message, setMessage] = useState("Drop an APK file here or select one to begin.");
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const timerRef = useRef<number | null>(null);

  const formatFileSize = (size: number | null) => {
    if (size === null) {
      return "—";
    }

    if (size < 1024) {
      return `${size} B`;
    }

    if (size < 1024 * 1024) {
      return `${(size / 1024).toFixed(1)} KB`;
    }

    return `${(size / (1024 * 1024)).toFixed(2)} MB`;
  };

  const statusConfig = {
    idle: {
      label: "Awaiting APK",
      icon: UploadCloud,
      tone: "border-primary/20 bg-primary/10 text-primary",
    },
    uploading: {
      label: "Scanning",
      icon: LoaderCircle,
      tone: "border-amber-400/20 bg-amber-400/10 text-amber-200",
    },
    success: {
      label: "Analysis queued",
      icon: ShieldCheck,
      tone: "border-emerald-400/20 bg-emerald-400/10 text-emerald-200",
    },
    error: {
      label: "Blocked",
      icon: AlertTriangle,
      tone: "border-red-400/20 bg-red-400/10 text-red-200",
    },
  }[state];

  const StatusIcon = statusConfig.icon;

  useEffect(() => {
    return () => {
      if (timerRef.current) {
        window.clearInterval(timerRef.current);
      }
    };
  }, []);

  const validateFile = (file: File | null) => {
    if (!file) {
      return { valid: false, reason: "No file selected." };
    }

    const isApk = file.name.toLowerCase().endsWith(".apk");

    if (!isApk) {
      return { valid: false, reason: "Only .apk files are allowed." };
    }

    return { valid: true, reason: "" };
  };

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

    if (timerRef.current) {
      window.clearInterval(timerRef.current);
    }

    const xhr = new XMLHttpRequest();
    const formData = new FormData();
    formData.append("file", file);

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        const percentComplete = Math.round((event.loaded / event.total) * 100);
        // Cap upload progress at 90% until backend processes it
        setProgress(Math.min(percentComplete, 90));
      }
    };

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const response = JSON.parse(xhr.responseText);
          setProgress(100);
          setState("success");
          setMessage(`${file.name} uploaded. Forwarding to analysis engine...`);
          window.setTimeout(() => router.push(`/analysis?report_id=${response.report_id}`), 800);
        } catch (e) {
          setState("error");
          setMessage("Failed to parse server response.");
        }
      } else {
        setState("error");
        setProgress(0);
        try {
            const errResponse = JSON.parse(xhr.responseText);
            setMessage(`Upload failed: ${errResponse.detail || xhr.statusText}`);
        } catch(e) {
            setMessage(`Upload failed with status: ${xhr.status}`);
        }
      }
    };

    xhr.onerror = () => {
      setState("error");
      setProgress(0);
      setMessage("Network error occurred during upload.");
    };

    xhr.open("POST", "http://localhost:8000/api/upload-apk", true);
    xhr.send(formData);
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0] ?? null;
    if (selectedFile) {
      startUpload(selectedFile);
    }
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);

    const droppedFile = event.dataTransfer.files?.[0] ?? null;
    if (droppedFile) {
      startUpload(droppedFile);
    }
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

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
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
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
                <Package className="h-7 w-7" aria-hidden="true" />
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
                      <StatusIcon className={`h-4 w-4 ${state === "uploading" ? "animate-spin" : ""}`} aria-hidden="true" />
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
                  state === "success"
                    ? "bg-emerald-400"
                    : state === "error"
                    ? "bg-red-400"
                    : "bg-gradient-to-r from-primary via-secondary to-accent"
                }`}
                style={{ width: `${progress}%` }}
              />
            </div>

            <div className={`mt-5 rounded-2xl border p-4 ${statusConfig.tone}`}>
              <p className="text-xs uppercase tracking-[0.24em] text-white/70">Upload Status</p>
              <p className="mt-2 text-sm font-medium text-white">{message}</p>
              <div className="mt-4 flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-white/70">
                <StatusIcon className={`h-4 w-4 ${state === "uploading" ? "animate-spin" : ""}`} aria-hidden="true" />
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