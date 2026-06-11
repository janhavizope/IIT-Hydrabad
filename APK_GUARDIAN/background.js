console.log("[APK Guardian] [INIT] Service worker loaded with Production Architecture");

const scannedUrls = new Set();
const CACHE_TIME = 10 * 60 * 1000; // 10 minutes

function isApk(url, filename) {
    if (!url) return false;
    const lowerUrl = url.toLowerCase();
    const lowerFilename = (filename || "").toLowerCase();
    return lowerFilename.endsWith(".apk") || lowerUrl.includes(".apk");
}

function setBadge(text, color) {
    chrome.action.setBadgeText({ text: text }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ color: color }).catch(() => {});
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 60000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(id);
        return response;
    } catch (err) {
        clearTimeout(id);
        if (err.name === 'AbortError') {
            throw new Error('Request timed out');
        }
        throw err;
    }
}

chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
    const downloadUrl = item.finalUrl || item.url;

    if (!isApk(downloadUrl, item.filename)) {
        suggest();
        return false;
    }

    if (scannedUrls.has(downloadUrl)) {
        console.log(`[APK Guardian] [URL_RESOLUTION] URL already scanned recently: ${downloadUrl}`);
        suggest();
        return false;
    }

    console.log("[APK Guardian] [URL_RESOLUTION] APK detected → Intercepting via onDeterminingFilename");
    scannedUrls.add(downloadUrl);
    setBadge("SCAN", "#FFA500"); // Orange indicating scanning

    setTimeout(() => {
        scannedUrls.delete(downloadUrl);
    }, CACHE_TIME);

    checkApkBackend(item, downloadUrl, suggest);

    return true; // Asynchronous
});

async function checkApkBackend(item, downloadUrl, suggest) {
    const startTime = Date.now();

    try {

        console.log(`[APK Guardian] [ANALYSIS] Sending URL directly to backend pipeline: ${downloadUrl}`);
        
        // 60-second timeout for backend analysis
        const response = await fetchWithTimeout("http://127.0.0.1:8000/api/scan-apk", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ apk_url: downloadUrl })
        }, 60000);

        let result;
        try {
            result = await response.json();
        } catch (e) {
            console.log("[APK Guardian] [ANALYSIS] Invalid JSON response from backend.");
            setBadge("ERR", "#808080");
            suggest();
            setTimeout(() => chrome.downloads.pause(item.id), 100);
            return;
        }

        let verdict = result?.verdict || "SUSPICIOUS"; // Never UNKNOWN
        let reasons = result?.reasons || [];
        const processTime = ((Date.now() - startTime) / 1000).toFixed(2);
        
        console.log(`[APK Guardian] [ANALYSIS] Verdict evaluated as: ${verdict} (Score: ${result?.risk_score || 0}) in ${processTime}s`);
        if (reasons.length > 0) {
            console.log(`[APK Guardian] [ANALYSIS] Reasons: ${reasons.join(" | ")}`);
        }

        if (verdict === "SAFE") {
            console.log("[APK Guardian] [DECISION] ALLOWING download (SAFE)");
            setBadge("SAFE", "#00FF00");
            suggest();
        } else if (verdict === "MALICIOUS") {
            console.log("[APK Guardian] [DECISION] BLOCKING download (Malicious APK detected)");
            setBadge("BLOCK", "#FF0000");
            chrome.downloads.cancel(item.id, () => {
                suggest();
            });
        } else {
            console.log(`[APK Guardian] [DECISION] ${verdict} download. Pausing for explicit user confirmation.`);
            setBadge("WARN", "#FFFF00");
            suggest();
            setTimeout(() => chrome.downloads.pause(item.id), 100);
        }

    } catch (err) {
        console.log(`[APK Guardian] [ANALYSIS] Interception Error: ${err.message}`);
        setBadge("ERR", "#808080");
        console.log("[APK Guardian] [DECISION] Pausing download due to extension error.");
        suggest();
        setTimeout(() => chrome.downloads.pause(item.id), 100);
    }
}

chrome.downloads.onCreated.addListener((item) => {
    const downloadUrl = item.finalUrl || item.url;
    if (isApk(downloadUrl, item.filename)) {
        console.log(`[APK Guardian] [URL_RESOLUTION] onCreated tracking APK download: ${downloadUrl}`);
    }
});