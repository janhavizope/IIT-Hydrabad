const params = new URLSearchParams(location.search);
const dlId = parseInt(params.get('dlId'));

function loadResult() {
  chrome.storage.local.get(`scanResult_${dlId}`, (data) => {
    const result = data[`scanResult_${dlId}`];
    if (!result) { setTimeout(loadResult, 400); return; }
    applyResult(result);
  });
}

function applyResult(result) {
  const isMalicious = result.verdict === 'MALICIOUS';
  const cls = isMalicious ? 'malicious' : 'suspicious';
  document.getElementById('threatBanner').className = 'threat-banner ' + cls;
  const icon = document.getElementById('threatIcon');
  if (isMalicious) {
    icon.setAttribute('stroke', '#f87171');
    icon.innerHTML = `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>`;
  }
  document.getElementById('threatTitle').textContent = isMalicious ? 'Malicious File' : 'Suspicious File';
  document.getElementById('threatSub').textContent = isMalicious ? 'Threat confirmed — download blocked' : 'Download paused for review';
  const badge = document.getElementById('verdictBadge');
  badge.className = 'verdict-badge ' + cls;
  badge.textContent = result.verdict;
  document.getElementById('infoFile').textContent = result.filename || '—';
  document.getElementById('infoScore').textContent = result.riskScore + ' / 100';
  const fill = document.getElementById('riskFill');
  fill.className = 'risk-fill ' + (result.riskScore >= 70 ? 'high' : 'med');
  setTimeout(() => { fill.style.width = result.riskScore + '%'; }, 100);
  const reasonsList = document.getElementById('reasonsList');
  (result.reasons || []).forEach(r => {
    const div = document.createElement('div');
    div.className = 'reason-item';
    div.innerHTML = `<div class="reason-dot ${cls}"></div><span>${r}</span>`;
    reasonsList.appendChild(div);
  });
  if (!isMalicious) document.getElementById('btnCancel').className = 'btn btn-cancel-suspicious';
  if (isMalicious) document.getElementById('cautionText').textContent = 'This file has been identified as malicious. Downloading may harm your device.';
}

function downloadAnyway() {
  chrome.runtime.sendMessage({ type: 'FORCE_DOWNLOAD', downloadId: dlId }, () => window.close());
}

function cancelDownload() {
  chrome.runtime.sendMessage({ type: 'CANCEL_DOWNLOAD', downloadId: dlId }, () => window.close());
}

document.getElementById('btnDownload').addEventListener('click', downloadAnyway);
document.getElementById('btnCancel').addEventListener('click', cancelDownload);

loadResult();