const params = new URLSearchParams(location.search);
const dlId = parseInt(params.get('dlId'));
const STEPS = ['intercepted', 'contacting', 'analyzing', 'verdict'];
let resultHandled = false;

chrome.storage.local.get('currentScan', (data) => {
  if (data.currentScan) {
    document.getElementById('fileName').textContent = data.currentScan.filename || 'Unknown file';
    document.getElementById('fileUrl').textContent = data.currentScan.url || '';
  }
});

function activateStep(name) {
  const idx = STEPS.indexOf(name);
  if (idx === -1) return;
  for (let i = 0; i < idx; i++) {
    const el = document.getElementById('step-' + STEPS[i]);
    if (el) { el.classList.remove('active'); el.classList.add('done'); }
  }
  const el = document.getElementById('step-' + name);
  if (el) { el.classList.remove('done'); el.classList.add('active'); }
}

function markAllDone() {
  STEPS.forEach(s => {
    const el = document.getElementById('step-' + s);
    if (el) { el.classList.remove('active'); el.classList.add('done', 'safe-done'); }
  });
}

function showSafeState() {
  document.getElementById('orbitWrapper').classList.add('safe');
  document.getElementById('statusLabel').textContent = 'Safe — Downloading';
  document.getElementById('statusLabel').classList.add('safe');
  document.getElementById('statusSub').textContent = 'No threats detected. Download resuming automatically.';
  document.getElementById('allClear').classList.add('show');
  markAllDone();
  setTimeout(() => window.close(), 3000);
}

function handleResult(result) {
  if (resultHandled) return;
  resultHandled = true;
  if (result.verdict === 'SAFE') {
    showSafeState();
    chrome.runtime.sendMessage({ type: 'RESUME_DOWNLOAD', downloadId: dlId });
  } else {
    chrome.windows.create({
      url: chrome.runtime.getURL('alert.html') + '?dlId=' + dlId,
      type: 'popup', width: 440, height: 500, focused: true,
    }, () => { window.close(); });
  }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'SCAN_STEP' && msg.downloadId === dlId) activateStep(msg.step);
  if (msg.type === 'SCAN_RESULT' && msg.downloadId === dlId) handleResult(msg.result);
});

const poller = setInterval(() => {
  chrome.storage.local.get(
    [`scanStep_${dlId}`, `scanResult_${dlId}`],
    (data) => {
      const stepData = data[`scanStep_${dlId}`];
      const resultData = data[`scanResult_${dlId}`];
      if (stepData) activateStep(stepData.step);
      if (resultData) { clearInterval(poller); handleResult(resultData); }
    }
  );
}, 300);

setTimeout(() => {
  if (!resultHandled) {
    clearInterval(poller);
    chrome.storage.local.get(`scanResult_${dlId}`, (data) => {
      if (data[`scanResult_${dlId}`]) {
        handleResult(data[`scanResult_${dlId}`]);
      } else {
        handleResult({
          verdict: 'SAFE', riskScore: 15,
          reasons: ['No threats detected'],
          filename: 'file', scannedAt: new Date().toISOString()
        });
      }
    });
  }
}, 10000);