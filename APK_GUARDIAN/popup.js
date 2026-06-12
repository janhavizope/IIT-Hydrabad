function loadHistory() {
  chrome.runtime.sendMessage({ type: 'GET_HISTORY' }, (resp) => {
    if (chrome.runtime.lastError) return;
    const history = (resp && resp.history) || [];
    let safe = 0, suspicious = 0, malware = 0;
    history.forEach(h => {
      if (h.verdict === 'SAFE') safe++;
      else if (h.verdict === 'SUSPICIOUS') suspicious++;
      else if (h.verdict === 'MALICIOUS') malware++;
    });
    document.getElementById('stat-safe').textContent = safe;
    document.getElementById('stat-suspicious').textContent = suspicious;
    document.getElementById('stat-malware').textContent = malware;
    const list = document.getElementById('scanList');
    if (history.length === 0) {
      list.innerHTML = `<div class="empty-state"><div class="empty-icon">🛡️</div><div>No scans yet</div><div style="color:#334155; margin-top:4px">Guardian is watching your downloads</div></div>`;
      return;
    }
    list.innerHTML = '';
    history.slice(0, 20).forEach(item => {
      const scoreClass = item.riskScore >= 70 ? 'high' : item.riskScore >= 40 ? 'med' : 'low';
      const div = document.createElement('div');
      div.className = 'scan-item';
      div.innerHTML = `<div class="verdict-dot ${item.verdict}"></div><div class="scan-name" title="${item.filename}">${item.filename}</div><div class="scan-score ${scoreClass}">${item.riskScore}/100</div>`;
      list.appendChild(div);
    });
  });
}
document.getElementById('refresh-btn').addEventListener('click', loadHistory);
loadHistory();