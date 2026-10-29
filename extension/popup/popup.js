// PrivacyLens - Extension Popup Controller
// Communicates with Content Script and Local Python Backend

const BACKEND_URL = "http://127.0.0.1:8000";

document.addEventListener("DOMContentLoaded", async () => {
  const toggleProtection = document.getElementById("toggle-protection");
  const backendStatusBar = document.getElementById("backend-status-bar");
  const statusPulse = document.getElementById("status-pulse");
  const statusText = document.getElementById("status-text");
  const statusBadge = document.getElementById("status-badge");

  const statCount = document.getElementById("stat-count");
  const statTokens = document.getElementById("stat-tokens");
  const statEgress = document.getElementById("stat-egress");

  const btnScanPage = document.getElementById("btn-scan-page");
  const btnOpenProofLab = document.getElementById("btn-open-proof-lab");
  const btnOpenDashboard = document.getElementById("btn-open-dashboard");
  const btnCopyPreview = document.getElementById("btn-copy-preview");
  const scanMetaBar = document.getElementById("scan-meta-bar");
  const scanIdDisplay = document.getElementById("scan-id-display");
  const scanTimeDisplay = document.getElementById("scan-time-display");

  const findingsList = document.getElementById("findings-list");
  const previewText = document.getElementById("preview-text");
  const tabLinks = document.querySelectorAll(".tab-link");
  const tabPanes = document.querySelectorAll(".tab-pane");

  let isBackendOnline = false;
  let currentSanitizedContent = "";

  // 1. Tab Switching
  tabLinks.forEach(link => {
    link.addEventListener("click", () => {
      tabLinks.forEach(l => l.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));
      link.classList.add("active");
      const target = link.getAttribute("data-tab");
      document.getElementById(target).classList.add("active");
    });
  });

  // 2. Load Protection State
  if (chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["protectionEnabled"], (res) => {
      if (res.protectionEnabled !== undefined) {
        toggleProtection.checked = res.protectionEnabled;
      }
    });
  }

  toggleProtection.addEventListener("change", () => {
    const enabled = toggleProtection.checked;
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ protectionEnabled: enabled });
    }
    if (chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ action: "toggleProtection", enabled: enabled });
    }
  });

  // 3. Ping Backend Health
  async function checkBackendHealth() {
    try {
      const resp = await fetch(`${BACKEND_URL}/health`, { method: "GET" });
      const data = await resp.json();
      if (data.status === "ok") {
        isBackendOnline = true;
        backendStatusBar.className = "backend-status-card connected";
        statusPulse.className = "pulse-indicator green";
        statusText.innerText = "Firewall Engine Connected";
        statusBadge.innerText = "ONLINE";
        btnScanPage.disabled = !toggleProtection.checked;
      } else {
        throw new Error("Unexpected status");
      }
    } catch (err) {
      isBackendOnline = false;
      backendStatusBar.className = "backend-status-card disconnected";
      statusPulse.className = "pulse-indicator red";
      statusText.innerText = "Backend Offline (Port 8000)";
      statusBadge.innerText = "DISCONNECTED";
      btnScanPage.disabled = true;
    }
  }

  await checkBackendHealth();

  // 4. Open Dashboard & Proof Lab
  if (btnOpenProofLab) {
    btnOpenProofLab.addEventListener("click", () => {
      const url = `${BACKEND_URL}/#proof-lab`;
      if (chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url });
      } else {
        window.open(url, "_blank");
      }
    });
  }

  btnOpenDashboard.addEventListener("click", () => {
    if (chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: `${BACKEND_URL}/` });
    } else {
      window.open(`${BACKEND_URL}/`, "_blank");
    }
  });

  // 5. Scan Active Tab Content
  btnScanPage.addEventListener("click", async () => {
    if (!isBackendOnline) {
      alert("PrivacyLens backend is disconnected. Please ensure the Python server is running on http://127.0.0.1:8000");
      return;
    }

    btnScanPage.disabled = true;
    btnScanPage.innerText = "Scanning Page...";

    try {
      // Query active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) throw new Error("No active tab found");

      // Request content extraction from content script
      let pageData;
      try {
        const resp = await chrome.tabs.sendMessage(tab.id, { action: "getPageContent" });
        pageData = resp ? resp.data : null;
      } catch (err) {
        // Fallback: inject content script on the fly if needed
        const [res] = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => ({
            title: document.title,
            url: window.location.href,
            text: document.body ? document.body.innerText : ""
          })
        });
        pageData = res ? res.result : null;
      }

      if (!pageData || !pageData.text) {
        throw new Error("Could not extract page text from active tab");
      }

      // Step A: Call Backend /scan
      const scanResp = await fetch(`${BACKEND_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: pageData.text,
          url: pageData.url,
          title: pageData.title
        })
      });
      const scanData = await scanResp.json();

      // Step B: Call Backend /sanitize
      const sanitizeResp = await fetch(`${BACKEND_URL}/sanitize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: pageData.text,
          url: pageData.url
        })
      });
      const sanitizeData = await sanitizeResp.json();

      // Render scan ID & timestamp
      if (scanData.scan_id && scanMetaBar) {
        scanIdDisplay.innerText = scanData.scan_id;
        scanTimeDisplay.innerText = new Date().toLocaleTimeString();
        scanMetaBar.style.display = "flex";
      }

      // Render findings
      const findings = scanData.findings || [];
      statCount.innerText = findings.length;
      statTokens.innerText = (sanitizeData.tokens || []).length;
      statEgress.innerText = "CLEARED";

      renderFindingsList(findings);

      // Render sanitized preview
      currentSanitizedContent = sanitizeData.sanitized_content || "";
      previewText.innerText = currentSanitizedContent.slice(0, 1500) + (currentSanitizedContent.length > 1500 ? "\n\n...[Truncated for preview]" : "");

      // Update badge count
      if (chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ action: "updateBadge", count: findings.length });
      }

    } catch (err) {
      findingsList.innerHTML = `<div class="empty-state" style="color:#fb7185;">Scan error: ${err.message}</div>`;
    } finally {
      btnScanPage.disabled = false;
      btnScanPage.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Scan Current Page`;
    }
  });

  function renderFindingsList(findings) {
    if (findings.length === 0) {
      findingsList.innerHTML = `<div class="empty-state" style="color:#34d399;">✓ No sensitive PII or credentials detected on this page.</div>`;
      return;
    }

    findingsList.innerHTML = findings.map(f => {
      const typeLower = (f.type || "").toLowerCase();
      let catClass = "cat-credential";
      if (typeLower.includes("card")) catClass = "cat-card";
      else if (typeLower.includes("aadhaar")) catClass = "cat-aadhaar";
      else if (typeLower.includes("pan")) catClass = "cat-pan";
      else if (typeLower.includes("upi")) catClass = "cat-upi";

      const confPct = Math.round((f.confidence || 0.95) * 100);

      return `
        <div class="finding-item">
          <div class="item-left">
            <span class="cat-pill ${catClass}">${escapeHtml(f.type)}</span>
            <span class="item-reason">${escapeHtml(f.reason || "Pattern match")}</span>
          </div>
          <span class="item-conf">${confPct}%</span>
        </div>
      `;
    }).join("");
  }

  // Copy Preview
  btnCopyPreview.addEventListener("click", () => {
    if (currentSanitizedContent) {
      navigator.clipboard.writeText(currentSanitizedContent);
      btnCopyPreview.innerText = "Copied!";
      setTimeout(() => { btnCopyPreview.innerText = "Copy"; }, 1500);
    }
  });

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
});
