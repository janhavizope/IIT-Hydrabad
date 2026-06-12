const pendingScans = {};

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const url = downloadItem.url || "";
  const filename = downloadItem.filename || "";

  const blockedExtensions = /\.(apk|exe|zip|dmg|msi|pkg|deb|rpm|bat|sh|jar|ipa|xapk|apks)(\?.*)?$/i;

  const isTargeted =
    blockedExtensions.test(url) ||
    blockedExtensions.test(filename) ||
    downloadItem.mime === "application/vnd.android.package-archive" ||
    downloadItem.mime === "application/octet-stream" ||
    downloadItem.mime === "application/x-msdownload";

  if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return;
  if (!isTargeted) return;

  try {
    await chrome.downloads.pause(downloadItem.id);
  } catch (e) {
    console.log("Could not pause:", e);
  }

  await chrome.storage.local.set({
    currentScan: {
      downloadId: downloadItem.id,
      url: downloadItem.url,
      filename: getFilename(downloadItem.filename || downloadItem.url),
      startTime: Date.now(),
    },
  });

  chrome.windows.create({
    url: chrome.runtime.getURL("scanning.html") + "?dlId=" + downloadItem.id,
    type: "popup",
    width: 420,
    height: 580,
    focused: true,
  });

  performScan(downloadItem);
});

async function performScan(downloadItem) {
  const dlId = downloadItem.id;
  const filename = getFilename(downloadItem.filename || downloadItem.url);

  await updateScanStep(dlId, "intercepted");
  await sleep(800);

  await updateScanStep(dlId, "contacting");
  await sleep(600);

  const result = heuristicScan(downloadItem.url, filename);

  await updateScanStep(dlId, "analyzing");
  await sleep(900);

  await updateScanStep(dlId, "verdict", result);
  await sleep(400);

  await chrome.storage.local.set({ [`scanResult_${dlId}`]: result });

  // If unsafe - cancel download IMMEDIATELY
  if (result.verdict !== "SAFE") {
    try {
      chrome.downloads.cancel(dlId);
    } catch (e) {}
  }

  chrome.runtime.sendMessage({
    type: "SCAN_RESULT",
    downloadId: dlId,
    result,
  }).catch(() => {});

  saveScanHistory(filename, result);
}

function heuristicScan(url, filename) {
  const suspiciousPatterns = [
    /insecure/i, /malware/i, /virus/i, /crack/i, /hack/i,
    /mod/i, /free.*premium/i, /keygen/i, /patch/i, /trojan/i,
    /exploit/i, /payload/i, /inject/i, /rootkit/i,
  ];

  const trustedDomains = [
    "play.google.com", "apkmirror.com", "apkpure.com",
    "github.com", "whatsapp.com", "instagram.com",
    "google.com", "microsoft.com", "apple.com",
    "python.org", "videolan.org", "notepad-plus-plus.org",
    "7-zip.org", "mozilla.org", "opera.com",
  ];

  let riskScore = 20;
  const reasons = [];
  let verdict = "SAFE";

  try {
    const domain = new URL(url).hostname;
    const isTrusted = trustedDomains.some((d) => domain.includes(d));
    if (!isTrusted) {
      riskScore += 20;
      reasons.push("Low domain trust");
    }
    if (/^\d+\.\d+\.\d+\.\d+/.test(domain)) {
      riskScore += 30;
      reasons.push("IP address instead of domain");
    }
  } catch (e) {}

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(filename) || pattern.test(url)) {
      riskScore += 25;
      reasons.push("Suspicious filename pattern");
      break;
    }
  }

  if ((url.match(/%[0-9a-f]{2}/gi) || []).length > 5) {
    riskScore += 15;
    reasons.push("Obfuscated URL detected");
  }

  if (url.includes("track") || url.includes("beacon") || url.includes("pixel")) {
    riskScore += 10;
    reasons.push("Data exfiltration pattern");
  }

  if (filename.toLowerCase().endsWith(".apk")) {
    const domain = (() => { try { return new URL(url).hostname; } catch { return ""; } })();
    const isTrusted = trustedDomains.some((d) => domain.includes(d));
    if (!isTrusted) {
      riskScore += 20;
      reasons.push("APK from untrusted source");
    }
  }

  riskScore = Math.min(riskScore, 100);

  if (riskScore >= 70) verdict = "MALICIOUS";
  else if (riskScore >= 40) verdict = "SUSPICIOUS";
  else verdict = "SAFE";

  return {
    verdict,
    riskScore,
    reasons: reasons.length > 0 ? reasons : ["No threats detected"],
    filename,
    scannedAt: new Date().toISOString(),
  };
}

async function updateScanStep(dlId, step, result = null) {
  await chrome.storage.local.set({
    [`scanStep_${dlId}`]: { step, result, timestamp: Date.now() },
  });
  chrome.runtime.sendMessage({
    type: "SCAN_STEP",
    downloadId: dlId,
    step,
    result,
  }).catch(() => {});
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_SCAN_STATUS") {
    chrome.storage.local.get([
      `scanStep_${msg.downloadId}`,
      `scanResult_${msg.downloadId}`,
    ], (data) => {
      sendResponse({
        step: data[`scanStep_${msg.downloadId}`],
        result: data[`scanResult_${msg.downloadId}`],
      });
    });
    return true;
  }

  if (msg.type === "RESUME_DOWNLOAD") {
    // Only resume if verdict is SAFE
    chrome.storage.local.get(`scanResult_${msg.downloadId}`, (data) => {
      const result = data[`scanResult_${msg.downloadId}`];
      if (result && result.verdict === "SAFE") {
        chrome.downloads.resume(msg.downloadId, () => {
          if (chrome.runtime.lastError) {
            chrome.storage.local.get("currentScan", (d) => {
              if (d.currentScan) chrome.downloads.download({ url: d.currentScan.url });
            });
          }
        });
      } else {
        // Not safe - cancel
        chrome.downloads.cancel(msg.downloadId);
      }
    });
    sendResponse({ ok: true });
  }

  if (msg.type === "CANCEL_DOWNLOAD") {
    chrome.downloads.cancel(msg.downloadId);
    chrome.downloads.erase({ id: msg.downloadId });
    sendResponse({ ok: true });
  }

  if (msg.type === "FORCE_DOWNLOAD") {
    // User clicked Download Anyway
    chrome.downloads.resume(msg.downloadId, () => {
      if (chrome.runtime.lastError) {
        chrome.storage.local.get("currentScan", (data) => {
          if (data.currentScan) chrome.downloads.download({ url: data.currentScan.url });
        });
      }
    });
    sendResponse({ ok: true });
  }

  if (msg.type === "GET_HISTORY") {
    chrome.storage.local.get("scanHistory", (data) => {
      sendResponse({ history: data.scanHistory || [] });
    });
    return true;
  }
});

function saveScanHistory(filename, result) {
  chrome.storage.local.get("scanHistory", (data) => {
    const history = data.scanHistory || [];
    history.unshift({
      filename,
      verdict: result.verdict,
      riskScore: result.riskScore,
      scannedAt: result.scannedAt,
    });
    if (history.length > 50) history.splice(50);
    chrome.storage.local.set({ scanHistory: history });
  });
}

function getFilename(urlOrPath) {
  if (!urlOrPath) return "unknown.apk";
  try {
    const parts = urlOrPath.split(/[/?#]/);
    const name = parts[parts.length - 1] || parts[parts.length - 2] || "file";
    return decodeURIComponent(name).split("?")[0] || "unknown.apk";
  } catch {
    return "unknown.apk";
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}