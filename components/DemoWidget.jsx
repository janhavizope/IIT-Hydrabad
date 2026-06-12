"use client";
import { useState, useEffect, useRef } from "react";
import styles from "./DemoWidget.module.css";

// ── Fake scan log lines ──────────────────────────────────────────
const LOG_LINES = [
  { t: 300,  text: "► Unpacking APK archive…",               type: "info" },
  { t: 700,  text: "► Extracting AndroidManifest.xml",        type: "info" },
  { t: 1100, text: "► Decompiling DEX bytecode via jadx…",    type: "info" },
  { t: 1500, text: "► Scanning 847 Java class files…",        type: "info" },
  { t: 1900, text: "⚠  Dangerous permission: READ_CONTACTS",  type: "warn" },
  { t: 2200, text: "⚠  Dangerous permission: SEND_SMS",       type: "warn" },
  { t: 2500, text: "► Checking network traffic signatures…",  type: "info" },
  { t: 2800, text: "✗  Hardcoded API key detected in Base64", type: "danger" },
  { t: 3100, text: "► Running YARA malware ruleset…",         type: "info" },
  { t: 3400, text: "✗  Matched rule: SPYWARE_DataExfil_v3",   type: "danger" },
  { t: 3700, text: "► Analysing obfuscation patterns…",       type: "info" },
  { t: 4000, text: "⚠  Heavy string obfuscation detected",   type: "warn" },
  { t: 4300, text: "► Generating threat report…",             type: "info" },
  { t: 4600, text: "✔  Scan complete — Risk Score: 87 / 100", type: "success"},
];

// ── Threat report data ───────────────────────────────────────────
const REPORT = {
  appName:    "com.shady.tracker",
  version:    "2.4.1",
  size:       "14.3 MB",
  score:      87,
  level:      "HIGH",
  findings: [
    { cat: "Permissions",      icon: "🔐", sev: "danger", detail: "READ_CONTACTS, SEND_SMS, RECORD_AUDIO, ACCESS_FINE_LOCATION" },
    { cat: "Network Calls",    icon: "🌐", sev: "warn",   detail: "Exfil endpoint: api.shadow-track[.]ru/collect" },
    { cat: "Hardcoded Secret", icon: "🔑", sev: "danger", detail: "Firebase API key exposed in plain Base64 string" },
    { cat: "Malware Match",    icon: "🦠", sev: "danger", detail: "YARA: SPYWARE_DataExfil_v3 (confidence 94%)" },
    { cat: "Obfuscation",      icon: "🎭", sev: "warn",   detail: "ProGuard + custom string-encrypt layer detected" },
    { cat: "Crypto",           icon: "🔒", sev: "info",   detail: "AES-128 (weak IV) used for local data storage" },
  ],
};

// ── Helper ───────────────────────────────────────────────────────
function ScoreRing({ score }) {
  const r = 52, circ = 2 * Math.PI * r;
  const dash = circ - (score / 100) * circ;
  const color = score >= 70 ? "#ef4444" : score >= 40 ? "#f59e0b" : "#22c55e";
  return (
    <svg width="130" height="130" viewBox="0 0 130 130">
      <circle cx="65" cy="65" r={r} fill="none" stroke="#1e293b" strokeWidth="10" />
      <circle
        cx="65" cy="65" r={r} fill="none"
        stroke={color} strokeWidth="10"
        strokeDasharray={circ} strokeDashoffset={dash}
        strokeLinecap="round"
        transform="rotate(-90 65 65)"
        style={{ transition: "stroke-dashoffset 1s ease" }}
      />
      <text x="65" y="60" textAnchor="middle" fill={color} fontSize="26" fontWeight="800">{score}</text>
      <text x="65" y="78" textAnchor="middle" fill="#94a3b8" fontSize="11">/100</text>
    </svg>
  );
}

// ── Main component ────────────────────────────────────────────────
export default function DemoWidget() {
  // phase: "upload" | "scanning" | "report"
  const [phase, setPhase]       = useState("upload");
  const [progress, setProgress] = useState(0);
  const [logs, setLogs]         = useState([]);
  const [dragging, setDragging] = useState(false);
  const logRef                  = useRef(null);
  const timers                  = useRef([]);

  // cleanup on unmount
  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  // auto-scroll logs
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  function clearTimers() { timers.current.forEach(clearTimeout); timers.current = []; }

  function startScan() {
    clearTimers();
    setPhase("scanning");
    setProgress(0);
    setLogs([]);

    const totalMs = 5000;
    const tick    = 80;
    let elapsed   = 0;

    const progInterval = setInterval(() => {
      elapsed += tick;
      setProgress(Math.min(100, Math.round((elapsed / totalMs) * 100)));
      if (elapsed >= totalMs) clearInterval(progInterval);
    }, tick);

    LOG_LINES.forEach(({ t, text, type }) => {
      const id = setTimeout(() => setLogs(prev => [...prev, { text, type }]), t);
      timers.current.push(id);
    });

    const doneId = setTimeout(() => setPhase("report"), totalMs);
    timers.current.push(doneId);
  }

  function reset() {
    clearTimers();
    setPhase("upload");
    setProgress(0);
    setLogs([]);
  }

  // ── RENDER ────────────────────────────────────────────────────
  return (
    <div className={styles.wrapper}>
      {/* ── Header ── */}
      <div className={styles.header}>
        <span className={styles.logo}>
          <span className={styles.logoIcon}>🛡️</span> APK Shield
        </span>
        <span className={styles.badge}>Live Demo</span>
      </div>

      {/* ══════════ PHASE: UPLOAD ══════════ */}
      {phase === "upload" && (
        <div className={styles.uploadPhase}>
          <div
            className={`${styles.dropzone} ${dragging ? styles.dropzoneActive : ""}`}
            onDragOver={e => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={e => { e.preventDefault(); setDragging(false); startScan(); }}
            onClick={startScan}
          >
            <div className={styles.dropIcon}>📦</div>
            <p className={styles.dropTitle}>Drop your APK here</p>
            <p className={styles.dropSub}>or click to simulate upload</p>
            <div className={styles.fileTag}>.apk</div>
          </div>

          <div className={styles.statsRow}>
            <div className={styles.stat}><strong>48K+</strong><span>APKs Scanned</span></div>
            <div className={styles.stat}><strong>97.4%</strong><span>Accuracy</span></div>
            <div className={styles.stat}><strong>~2.1s</strong><span>Avg Scan Time</span></div>
          </div>

          <button className={styles.ctaBtn} onClick={startScan}>
            ▶ Upload APK &amp; Scan
          </button>
        </div>
      )}

      {/* ══════════ PHASE: SCANNING ══════════ */}
      {phase === "scanning" && (
        <div className={styles.scanPhase}>
          <div className={styles.phoneWrap}>
            <div className={styles.phone}>
              <div className={styles.phoneScanLine} />
              <span className={styles.phoneIcon}>📱</span>
            </div>
            <div className={styles.radarRing} style={{ animationDelay: "0s" }} />
            <div className={styles.radarRing} style={{ animationDelay: "0.5s" }} />
            <div className={styles.radarRing} style={{ animationDelay: "1s" }} />
          </div>

          <p className={styles.scanLabel}>Analysing APK… {progress}%</p>
          <div className={styles.progressBar}>
            <div className={styles.progressFill} style={{ width: `${progress}%` }} />
          </div>

          <div className={styles.logBox} ref={logRef}>
            {logs.map((l, i) => (
              <div key={i} className={`${styles.logLine} ${styles[`log_${l.type}`]}`}>
                {l.text}
              </div>
            ))}
            <div className={styles.logCursor}>_</div>
          </div>
        </div>
      )}

      {/* ══════════ PHASE: REPORT ══════════ */}
      {phase === "report" && (
        <div className={styles.reportPhase}>
          <div className={styles.reportTop}>
            <div className={styles.appMeta}>
              <p className={styles.appName}>{REPORT.appName}</p>
              <p className={styles.appSub}>v{REPORT.version} · {REPORT.size}</p>
            </div>
            <div className={styles.scoreWrap}>
              <ScoreRing score={REPORT.score} />
              <span className={styles.scoreLevel}>{REPORT.level} RISK</span>
            </div>
          </div>

          <div className={styles.findingsGrid}>
            {REPORT.findings.map((f, i) => (
              <div key={i} className={`${styles.findingCard} ${styles[`sev_${f.sev}`]}`}>
                <span className={styles.findingIcon}>{f.icon}</span>
                <div>
                  <p className={styles.findingCat}>{f.cat}</p>
                  <p className={styles.findingDetail}>{f.detail}</p>
                </div>
              </div>
            ))}
          </div>

          <div className={styles.verdict}>
            <span className={styles.verdictIcon}>⛔</span>
            <div>
              <strong>Recommended Action:</strong> Block &amp; Quarantine
              <p>This APK exhibits spyware behaviour. Do not install on any device.</p>
            </div>
          </div>

          <button className={styles.resetBtn} onClick={reset}>
            ↩ Scan Another APK
          </button>
        </div>
      )}
    </div>
  );
}