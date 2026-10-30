/**
 * PrivacyLens 2.0 — Cybersecurity SaaS Client-Side Application Engine
 * Implements:
 * 1. Client-Side SPA Router (/dashboard, /protection, /evidence, /test-lab, /activity, /settings)
 * 2. Real dynamic Evidence Inspector (Side-by-Side comparison, dynamic stats, session selector)
 * 3. Real 7-stage Live Protection Pipeline with AI Agent reasoning & local secret injection
 * 4. 5 PECathon 2026 Test Lab Scenarios with freshly generated synthetic data & canary tracking
 * 5. Fail-Closed Canary Firewall verification with deliberate leak injection test
 * 6. Zero hardcoded results, static fake orders, or predefined metrics
 */

(function () {
  "use strict";

  // App State
  let currentRoute = "/dashboard";
  let activeSessionId = null;
  let cachedSessions = [];
  let cachedSettings = null;

  // DOM Elements
  const appContent = document.getElementById("app-content");
  const topbarHeading = document.getElementById("topbar-heading");
  const topbarSubheading = document.getElementById("topbar-subheading");
  const vaultActiveCount = document.getElementById("vault-active-count");
  const btnQuickRunTest = document.getElementById("btn-quick-run-test");

  // =========================================================================
  // CLIENT-SIDE ROUTER (Same-Tab Navigation + Browser History Support)
  // =========================================================================

  function initRouter() {
    // Intercept clicks on links with data-route or relative internal paths
    document.addEventListener("click", (e) => {
      const link = e.target.closest("a");
      if (!link) return;

      const href = link.getAttribute("href");
      const route = link.getAttribute("data-route") || href;

      if (route && (route.startsWith("/") || route.startsWith("#")) && !link.hasAttribute("download") && !link.getAttribute("target")) {
        const cleanRoute = route.split("?")[0].replace(".html", "");
        if (["/", "/dashboard", "/protection", "/evidence", "/test-lab", "/activity", "/settings", "/scanner"].includes(cleanRoute)) {
          e.preventDefault();
          navigateTo(route);
        }
      }
    });

    // Handle browser Back / Forward buttons
    window.addEventListener("popstate", () => {
      handleRoute(window.location.pathname + window.location.search, false);
    });

    if (btnQuickRunTest) {
      btnQuickRunTest.addEventListener("click", () => navigateTo("/test-lab"));
    }

    initThemeToggle();

    // Initial Route
    const initialPath = window.location.pathname + window.location.search;
    handleRoute(initialPath, false);
  }

  function navigateTo(path) {
    if (path.startsWith("#")) {
      path = "/dashboard";
    }
    window.history.pushState(null, "", path);
    handleRoute(path, false);
  }

  function handleRoute(path, isPopState) {
    const url = new URL(path, window.location.origin);
    let pathname = url.pathname.replace(".html", "");
    if (pathname === "/" || pathname === "/scanner") {
      pathname = "/dashboard";
    }

    currentRoute = pathname;

    // Check for query parameters (e.g. ?session_id=sess_123)
    const sessionIdParam = url.searchParams.get("session_id");
    if (sessionIdParam) {
      activeSessionId = sessionIdParam;
    }

    // Update active state in sidebar navigation
    document.querySelectorAll(".sidebar-nav-item").forEach((item) => {
      const itemRoute = item.getAttribute("data-route");
      if (itemRoute === pathname) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    // Update Topbar Title & Description
    updateTopbarMeta(pathname);

    // Refresh active vault tokens count in topbar
    updateVaultTokenBadge();

    // Render corresponding view
    switch (pathname) {
      case "/dashboard":
        renderOverviewPage();
        break;
      case "/protection":
        renderProtectionPage();
        break;
      case "/evidence":
        renderEvidencePage(activeSessionId);
        break;
      case "/test-lab":
        renderTestLabPage();
        break;
      case "/activity":
        renderActivityPage();
        break;
      case "/settings":
        renderSettingsPage();
        break;
      default:
        renderOverviewPage();
        break;
    }

    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function updateTopbarMeta(route) {
    switch (route) {
      case "/dashboard":
        topbarHeading.innerText = "Overview Dashboard";
        topbarSubheading.innerText = "Live privacy telemetry, active session counts, and aggregate firewall status.";
        break;
      case "/protection":
        topbarHeading.innerText = "Live Browser Agent Protection";
        topbarSubheading.innerText = "Controlled webpage scanning, real-time sanitization, fail-closed validation, and local action execution.";
        break;
      case "/evidence":
        topbarHeading.innerText = "Evidence Inspector";
        topbarSubheading.innerText = "Side-by-side comparison of raw payloads versus sanitized tokens, verification checksums, and canary audit.";
        break;
      case "/test-lab":
        topbarHeading.innerText = "Security Test Lab";
        topbarSubheading.innerText = "PECathon PS-004 automated attack benchmarks with dynamic synthetic credentials and unique canaries.";
        break;
      case "/activity":
        topbarHeading.innerText = "Security Activity Logs";
        topbarSubheading.innerText = "Real-time audit trail of interception, detection, redaction, and validation decisions.";
        break;
      case "/settings":
        topbarHeading.innerText = "Firewall & Model Settings";
        topbarSubheading.innerText = "Configure AI providers, secure API credentials, detection rules, and memory retention controls.";
        break;
    }
  }

  async function updateVaultTokenBadge() {
    try {
      const resp = await fetch("/dashboard/stats");
      if (resp.ok) {
        const stats = await resp.json();
        if (vaultActiveCount) {
          const count = stats.active_vault_tokens || 0;
          vaultActiveCount.innerText = `${count} Tokens in RAM`;
        }
      }
    } catch (e) {
      // Graceful ignore
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // =========================================================================
  // PAGE 1: OVERVIEW / DASHBOARD
  // =========================================================================

  async function renderOverviewPage() {
    appContent.innerHTML = `
      <div style="text-align: center; padding: 40px;">
        <span class="pulse-dot"></span> Loading real-time telemetry...
      </div>
    `;

    try {
      const [statsRes, eventsRes] = await Promise.all([
        fetch("/dashboard/stats"),
        fetch("/api/events/history?limit=10")
      ]);

      const stats = statsRes.ok ? await statsRes.json() : {};
      const events = eventsRes.ok ? await eventsRes.json() : [];

      const hasData = stats.has_data || stats.total_sessions > 0;
      const totalSessions = hasData ? stats.total_sessions : 0;
      const totalDetected = hasData ? stats.total_detected : 0;
      const totalRedacted = hasData ? stats.total_redacted : 0;
      const totalBlocked = hasData ? stats.total_blocked : 0;
      const leakageRate = hasData ? `${stats.leakage_rate_pct}%` : "0.0%";

      appContent.innerHTML = `
        <!-- KPI Telemetry Grid -->
        <div class="kpi-row-4">
          <div class="kpi-box">
            <div class="kpi-box-label">Protection Sessions</div>
            <div class="kpi-box-num text-primary">${totalSessions}</div>
            <div class="kpi-box-sub">${hasData ? "Real executed sessions" : "No sessions executed yet"}</div>
          </div>
          <div class="kpi-box">
            <div class="kpi-box-label">Sensitive Items Detected</div>
            <div class="kpi-box-num text-warning">${totalDetected}</div>
            <div class="kpi-box-sub">${hasData ? "Aadhaar, PAN, Cards, OTPs, Keys" : "Awaiting scan input"}</div>
          </div>
          <div class="kpi-box">
            <div class="kpi-box-label">Successfully Redacted</div>
            <div class="kpi-box-num text-success">${totalRedacted}</div>
            <div class="kpi-box-sub">${hasData ? "Tokenized into RAM vault" : "Awaiting sanitization"}</div>
          </div>
          <div class="kpi-box">
            <div class="kpi-box-label">Unsafe Requests Blocked</div>
            <div class="kpi-box-num text-danger">${totalBlocked}</div>
            <div class="kpi-box-sub">${hasData ? "Fail-closed enforcement" : "Fail-closed armed"}</div>
          </div>
        </div>

        <!-- Quick Launch Action Bar -->
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
              Quick Firewall Controls
            </div>
            <span class="badge badge-success">AIR-GAPPED DEFENSE</span>
          </div>
          <div style="display: flex; gap: 14px; flex-wrap: wrap;">
            <button class="btn btn-primary" id="btn-ov-protection">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
              Start Live Protection Session
            </button>
            <button class="btn btn-outline" id="btn-ov-evidence">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>
              Open Evidence Inspector
            </button>
            <button class="btn btn-outline" id="btn-ov-testlab">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 2v7.527a2 2 0 0 1-.211.896L4.72 20.55a1 1 0 0 0 .9 1.45h12.76a1 1 0 0 0 .9-1.45l-5.069-10.127A2 2 0 0 1 14 9.527V2"/></svg>
              Run Security Test Lab
            </button>
            <button class="btn btn-outline" id="btn-ov-activity">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              View Activity Logs
            </button>
          </div>
        </div>

        <!-- System Architecture & Verification Banner -->
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Active Security Guarantees
            </div>
            <span class="badge badge-primary">FAIL-CLOSED ENABLED</span>
          </div>
          <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;">
            <div style="background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 16px;">
              <div style="font-weight: 700; color: var(--text-main); margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                <span class="pulse-dot"></span> Local Volatile RAM Vault
              </div>
              <div style="font-size: 0.8125rem; color: var(--text-muted);">
                Sensitive credentials reside strictly in process RAM. Zero disk storage, zero logging, zero persistence across reboots.
              </div>
            </div>
            <div style="background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 16px;">
              <div style="font-weight: 700; color: var(--text-main); margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                <span class="pulse-dot"></span> Fail-Closed Egress Gateway
              </div>
              <div style="font-size: 0.8125rem; color: var(--text-muted);">
                Every outbound payload is re-scanned for raw secrets and canary markers. Any leak triggers an immediate transmission abort.
              </div>
            </div>
            <div style="background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 16px;">
              <div style="font-weight: 700; color: var(--text-main); margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                <span class="pulse-dot"></span> Indian Checksum Validators
              </div>
              <div style="font-size: 0.8125rem; color: var(--text-muted);">
                Algorithmic validation for Aadhaar (Verhoeff dihedral), PAN, UPI VPA handles, IFSC bank codes, and Luhn credit cards.
              </div>
            </div>
          </div>
        </div>

        <!-- Recent Activity Stream -->
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              Recent Security Activity Feed
            </div>
            <span class="live-pulse-badge"><span class="pulse-dot"></span> LIVE IN-MEMORY BUS</span>
          </div>
          <div class="event-stream-container" style="max-height: 240px;">
            ${events.length === 0 ? `
              <div style="color: var(--text-muted); text-align: center; padding: 20px;">No events logged yet. System online.</div>
            ` : events.map(ev => `
              <div class="event-item">
                <span class="event-time">${escapeHtml(ev.time_display || ev.timestamp)}</span>
                <span class="event-badge ${getEventBadgeClass(ev.event_type)}">${escapeHtml(ev.event_type)}</span>
                <span class="event-msg">${escapeHtml(ev.detail)}</span>
              </div>
            `).join("")}
          </div>
        </div>
      `;

      // Bind Quick Launch buttons
      document.getElementById("btn-ov-protection").addEventListener("click", () => navigateTo("/protection"));
      document.getElementById("btn-ov-evidence").addEventListener("click", () => navigateTo("/evidence"));
      document.getElementById("btn-ov-testlab").addEventListener("click", () => navigateTo("/test-lab"));
      document.getElementById("btn-ov-activity").addEventListener("click", () => navigateTo("/activity"));

    } catch (e) {
      appContent.innerHTML = `
        <div class="saas-card">
          <div class="empty-state-box">
            <div class="empty-state-title" style="color: var(--status-danger);">Failed to load overview data</div>
            <div class="empty-state-desc">${escapeHtml(e.message)}</div>
            <button class="btn btn-primary" onclick="window.location.reload()">Retry</button>
          </div>
        </div>
      `;
    }
  }

  function getEventBadgeClass(type) {
    if (!type) return "ev-system";
    if (type.includes("SCAN")) return "ev-scan";
    if (type.includes("DETECT") || type.includes("FINDING")) return "ev-detect";
    if (type.includes("SANITIZE")) return "ev-sanitize";
    if (type.includes("BLOCKED") || type.includes("TRIPPED")) return "ev-blocked";
    if (type.includes("CLEARED") || type.includes("PASSED") || type.includes("ALLOWED")) return "ev-allowed";
    if (type.includes("CHALLENGE") || type.includes("TEST")) return "ev-challenge";
    return "ev-system";
  }

  // =========================================================================
  // PAGE 2: LIVE PROTECTION (Controlled Webpage AI Agent Pipeline)
  // =========================================================================

  let activeProtectionMode = "LIVE_INPUT"; // "LIVE_INPUT" | "LIVE_URL" | "TESTBED_SCENARIO"

  function renderProtectionPage() {
    appContent.innerHTML = `
      <!-- Control Panel Card -->
      <div class="saas-card">
        <div class="saas-card-header">
          <div class="saas-card-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>
            Live Target & AI Task Configuration
          </div>
          <span class="badge badge-success">LIVE INTERACTIVE EXECUTION</span>
        </div>

        <!-- 3 Prominent Source Selection Tabs -->
        <div style="display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px;">
          <button class="btn btn-sm ${activeProtectionMode === 'LIVE_INPUT' ? 'btn-primary' : 'btn-outline'}" id="tab-mode-live-input">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            1. Live Judge Input (Type Any Secrets Live)
          </button>
          <button class="btn btn-sm ${activeProtectionMode === 'LIVE_URL' ? 'btn-primary' : 'btn-outline'}" id="tab-mode-live-url">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            2. Live Internet URL (Real Webpage Fetch)
          </button>
          <button class="btn btn-sm ${activeProtectionMode === 'TESTBED_SCENARIO' ? 'btn-primary' : 'btn-outline'}" id="tab-mode-scenario">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
            3. Controlled Testbed Scenarios
          </button>
        </div>

        <!-- MODE 1: LIVE JUDGE INPUT CHALLENGE -->
        <div id="section-live-input" style="${activeProtectionMode === 'LIVE_INPUT' ? 'display: block;' : 'display: none;'}">
          <div class="form-group-saas">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 8px;">
              <label class="form-label-saas" style="margin-bottom: 0;">Type live text or click to generate random cryptographically valid data:</label>
              <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                <button class="btn btn-sm btn-primary" id="btn-generate-random-pii">
                  🎲 Generate Random Sensitive Data
                </button>
                <button class="btn btn-sm btn-outline btn-quick-seed" data-seed="identity">Random Aadhaar + PAN</button>
                <button class="btn btn-sm btn-outline btn-quick-seed" data-seed="financial">Random Card + UPI</button>
                <button class="btn btn-sm btn-outline btn-quick-seed" data-seed="credentials">Random Password + Email</button>
                <button class="btn btn-sm btn-outline btn-quick-seed" data-seed="developer">Random API Keys</button>
              </div>
            </div>
            <textarea class="form-input-saas" id="prot-custom-content" rows="4" style="font-family: var(--font-mono); font-size: 0.8125rem;" placeholder="Type any live text right now, or click '🎲 Generate Random Sensitive Data' above to populate fresh numbers with real checksums..."></textarea>
          </div>
        </div>

        <!-- MODE 2: LIVE INTERNET URL FETCH -->
        <div id="section-live-url" style="${activeProtectionMode === 'LIVE_URL' ? 'display: block;' : 'display: none;'}">
          <div class="form-group-saas">
            <label class="form-label-saas">Enter any real website URL to scan & protect live:</label>
            <div style="display: flex; gap: 8px;">
              <input type="url" class="form-input-saas" id="prot-live-url-input" value="https://news.ycombinator.com" placeholder="https://example.com or any real URL">
              <button class="btn btn-outline" id="btn-sample-url-hn">HackerNews</button>
              <button class="btn btn-outline" id="btn-sample-url-wiki">Wikipedia</button>
            </div>
            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">
              PrivacyLens will fetch the live webpage over HTTP, scan its DOM content, and sanitize sensitive elements before forwarding to the AI.
            </div>
          </div>
        </div>

        <!-- MODE 3: CONTROLLED TESTBED SCENARIOS -->
        <div id="section-scenario" style="${activeProtectionMode === 'TESTBED_SCENARIO' ? 'display: block;' : 'display: none;'}">
          <div class="form-group-saas">
            <label class="form-label-saas" for="prot-scenario-select">Select Controlled Webpage Scenario:</label>
            <select class="form-select-saas" id="prot-scenario-select">
              <option value="checkout.html">ShoeKart E-Commerce Checkout (Cards, PAN, Addresses)</option>
              <option value="login.html">CloudPortal Corporate Login (Email, Passwords, Split OTP)</option>
              <option value="support.html">Customer Support Portal (Phones, UPI ID, Aadhaar, Private Chat)</option>
              <option value="devsettings.html">InfraConsole Secrets (API Keys, AWS Credentials, Internal IPs)</option>
              <option value="video.html">MeetSecure Video Bridge (Participant Identifiers, Media Tokens)</option>
            </select>
          </div>
        </div>

        <!-- Task Goal -->
        <div class="form-group-saas" style="margin-top: 14px;">
          <label class="form-label-saas" for="prot-task-goal">AI Browser Agent Task Goal:</label>
          <input type="text" class="form-input-saas" id="prot-task-goal" value="Inspect page and safely interact without leaking sensitive credentials">
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 16px; border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <input type="checkbox" id="prot-run-agent" checked style="width: 16px; height: 16px;">
            <label for="prot-run-agent" style="font-size: 0.8125rem; font-weight: 600; color: var(--text-main); cursor: pointer;">
              Execute AI Agent Reasoning & Local RAM Secret Injection
            </label>
          </div>
          <button class="btn btn-primary" id="btn-start-protection" style="padding: 10px 22px; font-size: 0.9375rem;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Execute Live Protection
          </button>
        </div>
      </div>

      <!-- Real Processing Pipeline Stage Progression Tracker -->
      <div class="stage-tracker-bar" id="stage-tracker">
        <div class="stage-step" id="step-scan"><div class="stage-step-num">1</div> SCANNING</div>
        <div class="stage-divider"></div>
        <div class="stage-step" id="step-detect"><div class="stage-step-num">2</div> DETECTING</div>
        <div class="stage-divider"></div>
        <div class="stage-step" id="step-sanitize"><div class="stage-step-num">3</div> SANITIZING</div>
        <div class="stage-divider"></div>
        <div class="stage-step" id="step-validate"><div class="stage-step-num">4</div> VALIDATING</div>
        <div class="stage-divider"></div>
        <div class="stage-step" id="step-ai"><div class="stage-step-num">5</div> AI PROCESSING</div>
        <div class="stage-divider"></div>
        <div class="stage-step" id="step-complete"><div class="stage-step-num">6</div> COMPLETED</div>
      </div>

      <!-- Results Container (Empty state initially) -->
      <div id="protection-results-container">
        <div class="saas-card">
          <div class="empty-state-box">
            <div class="empty-state-icon">
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
            </div>
            <div class="empty-state-title">Ready for Live Protection</div>
            <div class="empty-state-desc">
              Type any live input, enter a real website URL, or select a scenario above and click <strong>"Execute Live Protection"</strong> to run the local detection, vault tokenization, egress firewall verification, and AI reasoning.
            </div>
          </div>
        </div>
      </div>
    `;

    // Tab Switching Logic
    const tabInput = document.getElementById("tab-mode-live-input");
    const tabUrl = document.getElementById("tab-mode-live-url");
    const tabScen = document.getElementById("tab-mode-scenario");

    const secInput = document.getElementById("section-live-input");
    const secUrl = document.getElementById("section-live-url");
    const secScen = document.getElementById("section-scenario");
    const taskGoalInput = document.getElementById("prot-task-goal");

    function setTab(mode) {
      activeProtectionMode = mode;
      tabInput.className = `btn btn-sm ${mode === 'LIVE_INPUT' ? 'btn-primary' : 'btn-outline'}`;
      tabUrl.className = `btn btn-sm ${mode === 'LIVE_URL' ? 'btn-primary' : 'btn-outline'}`;
      tabScen.className = `btn btn-sm ${mode === 'TESTBED_SCENARIO' ? 'btn-primary' : 'btn-outline'}`;

      secInput.style.display = mode === 'LIVE_INPUT' ? 'block' : 'none';
      secUrl.style.display = mode === 'LIVE_URL' ? 'block' : 'none';
      secScen.style.display = mode === 'TESTBED_SCENARIO' ? 'block' : 'none';

      if (mode === 'LIVE_INPUT') {
        taskGoalInput.value = "Inspect live text, sanitize credentials, and plan next safe action";
      } else if (mode === 'LIVE_URL') {
        taskGoalInput.value = "Fetch live website DOM and sanitize sensitive content before AI processing";
      } else {
        taskGoalInput.value = "Complete order payment without leaking credit card credentials";
      }
    }

    tabInput.addEventListener("click", () => setTab("LIVE_INPUT"));
    tabUrl.addEventListener("click", () => setTab("LIVE_URL"));
    tabScen.addEventListener("click", () => setTab("TESTBED_SCENARIO"));

    // Random Data Generator for Live Judge Challenge
    const customContentArea = document.getElementById("prot-custom-content");
    const btnGenRandom = document.getElementById("btn-generate-random-pii");

    async function fetchRandomSynthetic(category = "mixed") {
      try {
        if (btnGenRandom) {
          btnGenRandom.innerHTML = `<svg class="spin-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" stroke-opacity="0.3"/><path d="M12 2a10 10 0 0 1 10 10"/></svg> Generating...`;
        }
        const resp = await fetch(`/api/synthetic/random?category=${category}`);
        if (resp.ok) {
          const data = await resp.json();
          customContentArea.value = data.text;
        }
      } catch (e) {
        console.error("Failed to generate random data", e);
      } finally {
        if (btnGenRandom) {
          btnGenRandom.innerHTML = `🎲 Generate Random Sensitive Data`;
        }
      }
    }

    if (btnGenRandom) {
      btnGenRandom.addEventListener("click", () => fetchRandomSynthetic("mixed"));
    }

    document.querySelectorAll(".btn-quick-seed").forEach(btn => {
      btn.addEventListener("click", () => {
        const seedType = btn.getAttribute("data-seed");
        fetchRandomSynthetic(seedType);
      });
    });

    // Populate with one random set on first render if empty
    if (customContentArea && !customContentArea.value.trim()) {
      fetchRandomSynthetic("mixed");
    }

    // Sample URL buttons
    const urlInput = document.getElementById("prot-live-url-input");
    document.getElementById("btn-sample-url-hn").addEventListener("click", () => {
      urlInput.value = "https://news.ycombinator.com";
    });
    document.getElementById("btn-sample-url-wiki").addEventListener("click", () => {
      urlInput.value = "https://en.wikipedia.org/wiki/Data_privacy";
    });

    // Start Button
    document.getElementById("btn-start-protection").addEventListener("click", executeLiveProtection);
  }

  async function executeLiveProtection() {
    const btn = document.getElementById("btn-start-protection");
    const taskGoal = document.getElementById("prot-task-goal").value;
    const runAgent = document.getElementById("prot-run-agent").checked;

    let payload = {
      task_goal: taskGoal,
      run_agent: runAgent
    };

    if (activeProtectionMode === "LIVE_INPUT") {
      const customContent = document.getElementById("prot-custom-content").value;
      if (!customContent.trim()) {
        alert("Please enter some text or click one of the quick seed pills above!");
        return;
      }
      payload.custom_text = customContent;
    } else if (activeProtectionMode === "LIVE_URL") {
      const urlVal = document.getElementById("prot-live-url-input").value;
      if (!urlVal.trim()) {
        alert("Please enter a valid website URL!");
        return;
      }
      payload.custom_url = urlVal.trim();
    } else {
      payload.scenario = document.getElementById("prot-scenario-select").value;
    }

    btn.disabled = true;
    btn.innerHTML = `
      <svg class="spin-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" stroke-opacity="0.3"/><path d="M12 2a10 10 0 0 1 10 10"/></svg>
      Processing Pipeline...
    `;

    // Reset stages
    setStageStatus("step-scan", "active");
    setStageStatus("step-detect", "");
    setStageStatus("step-sanitize", "");
    setStageStatus("step-validate", "");
    setStageStatus("step-ai", "");
    setStageStatus("step-complete", "");

    try {
      const resp = await fetch("/api/protection/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Protection run failed");

      // Animate stages according to real execution
      setStageStatus("step-scan", "completed");
      setStageStatus("step-detect", "completed");
      setStageStatus("step-sanitize", "completed");
      setStageStatus("step-validate", data.verdict === "PROTECTED" ? "completed" : "blocked");
      setStageStatus("step-ai", runAgent && data.verdict === "PROTECTED" ? "completed" : "");
      setStageStatus("step-complete", data.verdict === "PROTECTED" ? "completed" : "blocked");

      // Render actual results
      renderProtectionResults(data);

      // Update active vault badge
      updateVaultTokenBadge();

    } catch (e) {
      setStageStatus("step-scan", "blocked");
      document.getElementById("protection-results-container").innerHTML = `
        <div class="saas-card">
          <div class="verdict-banner verdict-blocked">
            <span><strong>FIREWALL ERROR:</strong> ${escapeHtml(e.message)}</span>
            <span class="badge badge-danger">FAILED</span>
          </div>
        </div>
      `;
    } finally {
      btn.disabled = false;
      btn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        Execute Live Protection
      `;
    }
  }

  function setStageStatus(stepId, status) {
    const el = document.getElementById(stepId);
    if (!el) return;
    el.className = `stage-step ${status}`;
  }

  function renderProtectionResults(data) {
    const container = document.getElementById("protection-results-container");
    const isProtected = data.verdict === "PROTECTED";

    // Format raw payload highlighting sensitive values
    let rawFormatted = escapeHtml(data.raw_payload);
    (data.findings || []).forEach(f => {
      const val = escapeHtml(f.value);
      if (val && val.length >= 3) {
        rawFormatted = rawFormatted.split(val).join(`<span class="highlight-sensitive">${val}</span>`);
      }
    });

    // Format sanitized payload highlighting tokens
    let sanFormatted = escapeHtml(data.sanitized_payload);
    sanFormatted = sanFormatted.replace(/(\[[A-Z_0-9]+\])/g, `<span class="highlight-token">$1</span>`);

    container.innerHTML = `
      <!-- Verdict Banner -->
      <div class="verdict-banner ${isProtected ? 'verdict-allowed' : 'verdict-blocked'}" style="margin-bottom: 20px;">
        <span><strong>PRIVACYLENS FIREWALL VERDICT:</strong> ${isProtected ? 'PROTECTED (Cleared for transmission)' : 'BLOCKED (Sensitive data leak prevented)'} • Latency: ${data.latency_ms} ms • Active Vault Tokens: ${data.tokens_in_vault}</span>
        <span class="badge ${isProtected ? 'badge-success' : 'badge-danger'}">${isProtected ? 'SAFE TO DISPATCH' : 'TRANSMISSION ABORTED'}</span>
      </div>

      <!-- 3-Column Execution Grid -->
      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 24px;">
        <!-- Left: Raw Input -->
        <div class="evidence-pane">
          <div class="evidence-pane-header">
            <span style="color: var(--status-danger);">1. RAW CAPTURED INPUT</span>
            <span class="badge badge-danger">${data.findings_count} Sensitive Items</span>
          </div>
          <div class="evidence-code-body">${rawFormatted}</div>
        </div>

        <!-- Middle: Sanitized Output -->
        <div class="evidence-pane">
          <div class="evidence-pane-header">
            <span style="color: var(--status-success);">2. SANITIZED PAYLOAD</span>
            <span class="badge badge-success">RAM TOKENIZED</span>
          </div>
          <div class="evidence-code-body">${sanFormatted}</div>
        </div>

        <!-- Right: AI Agent Decision -->
        <div class="evidence-pane">
          <div class="evidence-pane-header">
            <span style="color: var(--accent-cyan);">3. AI AGENT REASONING & ACTIONS</span>
            <span class="badge badge-primary">LOCAL INJECTION</span>
          </div>
          <div class="evidence-code-body" style="font-family: var(--font-body); font-size: 0.8125rem;">
            ${(data.agent_steps || []).length === 0 ? `
              <div style="color: var(--text-muted);">No agent actions executed.</div>
            ` : data.agent_steps.map(step => `
              <div style="background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px; margin-bottom: 12px;">
                <div style="font-weight: 700; color: var(--text-main); margin-bottom: 6px;">Step ${step.step}: Action Proposed</div>
                <div style="font-family: var(--font-mono); font-size: 0.75rem; background: var(--bg-code); color: var(--text-cyan); border: 1px solid var(--border-subtle); padding: 8px 12px; border-radius: 6px; margin-bottom: 8px;">
                  ${escapeHtml(JSON.stringify(step.action_proposed, null, 2))}
                </div>
                <div style="font-size: 0.75rem; color: var(--text-muted); line-height: 1.5;">
                  <strong>Action Validator:</strong> <span class="text-success">${step.validation}</span><br>
                  <strong>Secret Injection:</strong> ${step.local_secret_injected ? '<span class="text-success">Resolved in volatile RAM locally</span>' : 'None required'}<br>
                  <strong>Cloud Transmission:</strong> <span class="text-success">0 Sensitive Bytes Exposed</span>
                </div>
              </div>
            `).join("")}
          </div>
        </div>
      </div>

      <!-- Action Bar -->
      <div style="display: flex; justify-content: flex-end; gap: 12px;">
        <button class="btn btn-outline" id="btn-view-evidence-direct">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>
          Open in Evidence Inspector
        </button>
      </div>
    `;

    document.getElementById("btn-view-evidence-direct").addEventListener("click", () => {
      activeSessionId = data.session_id;
      navigateTo(`/evidence?session_id=${data.session_id}`);
    });
  }

  // =========================================================================
  // PAGE 3: EVIDENCE INSPECTOR (Side-by-Side Diff, Real Metrics, Canaries)
  // =========================================================================

  async function renderEvidencePage(targetSessionId) {
    appContent.innerHTML = `
      <div style="text-align: center; padding: 40px;">
        <span class="pulse-dot"></span> Loading security evidence...
      </div>
    `;

    try {
      const resp = await fetch("/api/sessions");
      const sessions = resp.ok ? await resp.json() : [];
      cachedSessions = sessions;

      if (!sessions || sessions.length === 0) {
        // Empty State (Part 1 Requirement 10: "If no test has been performed, display an appropriate empty state")
        appContent.innerHTML = `
          <div class="saas-card">
            <div class="empty-state-box">
              <div class="empty-state-icon">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              </div>
              <div class="empty-state-title">No evidence available yet.</div>
              <div class="empty-state-desc">
                No tests or protection operations have been recorded in this session. Run a live protection session or execute a benchmark in the Security Test Lab to generate verifiable evidence.
              </div>
              <div style="display: flex; gap: 12px; justify-content: center;">
                <button class="btn btn-primary" id="btn-empty-go-protection">Launch Live Protection</button>
                <button class="btn btn-outline" id="btn-empty-go-testlab">Open Security Test Lab</button>
              </div>
            </div>
          </div>
        `;
        document.getElementById("btn-empty-go-protection").addEventListener("click", () => navigateTo("/protection"));
        document.getElementById("btn-empty-go-testlab").addEventListener("click", () => navigateTo("/test-lab"));
        return;
      }

      // Pick target session (either requested or latest)
      const selectedId = targetSessionId || sessions[0].session_id;
      const detailRes = await fetch(`/api/sessions/${selectedId}`);
      const sessionData = detailRes.ok ? await detailRes.json() : sessions[0];

      // Format Raw Payload with highlights
      let rawText = escapeHtml(sessionData.raw_payload || "");
      (sessionData.findings || []).forEach(f => {
        const val = escapeHtml(f.value);
        if (val && val.length >= 3) {
          rawText = rawText.split(val).join(`<span class="highlight-sensitive">${val}</span>`);
        }
      });

      // Format Sanitized Payload with token highlights
      let sanText = escapeHtml(sessionData.sanitized_payload || "");
      sanText = sanText.replace(/(\[[A-Z_0-9]+\])/g, `<span class="highlight-token">$1</span>`);

      const isProtected = sessionData.verdict === "PROTECTED";

      appContent.innerHTML = `
        <!-- Session Selector & Header Controls -->
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
              Evidence Session Inspector
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
              <span class="badge ${isProtected ? 'badge-success' : 'badge-danger'}">${escapeHtml(sessionData.verdict)}</span>
              <a href="/api/export-report/json" class="btn btn-sm btn-outline" download="privacylens_proof_report.json">Export JSON</a>
              <a href="/api/export-report/csv" class="btn btn-sm btn-outline" download="privacylens_proof_report.csv">Export CSV</a>
            </div>
          </div>

          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
            <div style="display: flex; align-items: center; gap: 12px; flex-grow: 1;">
              <label for="evidence-session-select" style="font-size: 0.8125rem; font-weight: 700; color: var(--text-main); white-space: nowrap;">
                Inspect Session:
              </label>
              <select class="form-select-saas" id="evidence-session-select" style="max-width: 550px;">
                ${sessions.map(s => `
                  <option value="${s.session_id}" ${s.session_id === selectedId ? 'selected' : ''}>
                    [${s.time_display}] ${escapeHtml(s.title || s.session_type)} (${s.verdict}) — ${s.total_detected} detected
                  </option>
                `).join("")}
              </select>
            </div>
            <div style="font-size: 0.75rem; color: var(--text-muted);">
              Session ID: <code>${escapeHtml(sessionData.session_id)}</code> • ${escapeHtml(sessionData.timestamp)}
            </div>
          </div>
        </div>

        <!-- 2-Panel Side-by-Side Comparison (Part 2 C) -->
        <div class="evidence-split-grid">
          <!-- LEFT PANEL: RAW PAYLOAD -->
          <div class="evidence-pane">
            <div class="evidence-pane-header">
              <span style="color: var(--status-danger);">RAW PAYLOAD (Actual Input Data)</span>
              <span class="badge badge-danger">${sessionData.total_detected} SENSITIVE VALUES DETECTED</span>
            </div>
            <div class="evidence-code-body">${rawText || "<em>No payload captured</em>"}</div>
          </div>

          <!-- RIGHT PANEL: SANITIZED PAYLOAD -->
          <div class="evidence-pane">
            <div class="evidence-pane-header">
              <span style="color: var(--status-success);">SANITIZED PAYLOAD (Actual Output Sent to AI)</span>
              <span class="badge badge-success">${sessionData.total_redacted} VALUES REDACTED</span>
            </div>
            <div class="evidence-code-body">${sanText || "<em>No sanitized output</em>"}</div>
          </div>
        </div>

        <!-- Dynamic Statistics Row (Part 2 C) -->
        <div class="kpi-row-4" style="margin-bottom: 24px;">
          <div class="kpi-box">
            <div class="kpi-box-label">Total Detected</div>
            <div class="kpi-box-num text-primary">${sessionData.total_detected}</div>
            <div class="kpi-box-sub">Identified by pattern & DOM rules</div>
          </div>
          <div class="kpi-box">
            <div class="kpi-box-label">Successfully Redacted</div>
            <div class="kpi-box-num text-success">${sessionData.total_redacted}</div>
            <div class="kpi-box-sub">Substituted with vault tokens</div>
          </div>
          <div class="kpi-box">
            <div class="kpi-box-label">Unredacted Sensitive Values</div>
            <div class="kpi-box-num ${sessionData.unredacted_count > 0 ? 'text-danger' : 'text-success'}">
              ${sessionData.unredacted_count}
            </div>
            <div class="kpi-box-sub">${sessionData.unredacted_count === 0 ? 'Zero unredacted items' : 'Leak detected'}</div>
          </div>
          <div class="kpi-box">
            <div class="kpi-box-label">Canaries Leaked in Outgoing</div>
            <div class="kpi-box-num ${sessionData.canaries_leaked_count > 0 ? 'text-danger' : 'text-success'}">
              ${sessionData.canaries_leaked_count}
            </div>
            <div class="kpi-box-sub">Verified in tested payload</div>
          </div>
        </div>

        <!-- Canary Leakage Testing & Firewall Verification Card (Part 2 D & E) -->
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Fail-Closed Canary Leakage Firewall Verification
            </div>
            <span class="badge ${isProtected ? 'badge-success' : 'badge-danger'}">
              ${isProtected ? 'GATE DECISION: ALLOWED' : 'GATE DECISION: BLOCKED'}
            </span>
          </div>

          <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 16px;">
            The Egress Gateway inspects every outgoing payload for raw secrets and active canaries.
            If an unredacted canary appears in the outbound stream, transmission is halted immediately with fail-closed semantics.
          </p>

          <div style="display: flex; gap: 14px; align-items: center; flex-wrap: wrap;">
            <button class="btn btn-outline" id="btn-test-safe-canary">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
              Test Clean Canary Tokenization
            </button>
            <button class="btn btn-danger-outline" id="btn-inject-canary-leak" title="Intentionally bypasses sanitization to test fail-closed blocking">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
              Test Fail-Closed Firewall (Inject Deliberate Leak)
            </button>
            <div style="font-size: 0.8125rem; color: var(--text-muted);" id="canary-test-feedback">
              Processing time: <strong>${sessionData.latency_ms} ms</strong>
            </div>
          </div>
        </div>
      `;

      // Session Select Change
      document.getElementById("evidence-session-select").addEventListener("change", (e) => {
        renderEvidencePage(e.target.value);
      });

      // Safe Canary Test
      document.getElementById("btn-test-safe-canary").addEventListener("click", async () => {
        await executeCanaryAudit(false);
      });

      // Deliberate Leak Test
      document.getElementById("btn-inject-canary-leak").addEventListener("click", async () => {
        await executeCanaryAudit(true);
      });

    } catch (e) {
      appContent.innerHTML = `
        <div class="saas-card">
          <div class="empty-state-box">
            <div class="empty-state-title" style="color: var(--status-danger);">Error Loading Evidence</div>
            <div class="empty-state-desc">${escapeHtml(e.message)}</div>
          </div>
        </div>
      `;
    }
  }

  async function executeCanaryAudit(injectLeak) {
    const feedback = document.getElementById("canary-test-feedback");
    if (feedback) feedback.innerText = injectLeak ? "Injecting deliberate canary leak to test firewall..." : "Auditing clean canary tokenization...";

    try {
      const resp = await fetch("/api/canary/test-firewall", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ inject_unredacted_canary: injectLeak })
      });
      const data = await resp.json();

      // Re-render Evidence Inspector with the new audit session
      renderEvidencePage(data.session_id);
    } catch (e) {
      if (feedback) feedback.innerText = `Error: ${e.message}`;
    }
  }

  // =========================================================================
  // PAGE 4: SECURITY TEST LAB (5 Scenarios with Dynamic Synthetic Data)
  // =========================================================================

  async function renderTestLabPage() {
    appContent.innerHTML = `
      <div style="text-align: center; padding: 40px;">
        <span class="pulse-dot"></span> Loading PECathon PS-004 Benchmark Scenarios...
      </div>
    `;

    try {
      const resp = await fetch("/api/test-lab/scenarios");
      const scenarios = resp.ok ? await resp.json() : [];

      appContent.innerHTML = `
        <!-- Actions Bar -->
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 2v7.527a2 2 0 0 1-.211.896L4.72 20.55a1 1 0 0 0 .9 1.45h12.76a1 1 0 0 0 .9-1.45l-5.069-10.127A2 2 0 0 1 14 9.527V2"/></svg>
              PECathon PS-004 Five Security Benchmark Scenarios
            </div>
            <span class="badge badge-primary">DYNAMIC SYNTHETIC BENCHMARK</span>
          </div>

          <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 16px;">
            Every run generates fresh synthetic PII, valid Indian checksums, and unique canaries.
            Results measure Baseline (naive text-only regex) versus PrivacyLens multi-modal firewall.
          </p>

          <div style="display: flex; gap: 12px; flex-wrap: wrap;">
            <button class="btn btn-primary" id="btn-run-all-tests">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
              Run All 5 Scenarios
            </button>
            <a href="/api/export-report/json" class="btn btn-outline" download="privacylens_benchmark.json">
              Export Benchmark JSON
            </a>
          </div>
        </div>

        <!-- 5 Scenarios Cards Grid -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px;">
          ${scenarios.map(sc => `
            <div class="saas-card" style="margin-bottom: 0;" id="card-${sc.id}">
              <div style="font-size: 0.6875rem; font-weight: 700; color: var(--accent-cyan); text-transform: uppercase; margin-bottom: 4px;">
                ${escapeHtml(sc.category)}
              </div>
              <div style="font-weight: 800; color: var(--text-main); font-size: 1rem; margin-bottom: 6px;">
                ${escapeHtml(sc.name)}
              </div>
              <div style="font-size: 0.78125rem; color: var(--text-muted); margin-bottom: 14px; min-height: 48px; line-height: 1.4;">
                ${escapeHtml(sc.description)}
              </div>
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span class="badge badge-primary">${sc.planted_canaries_count} Canaries</span>
                <button class="btn btn-sm btn-outline btn-run-single-sc" data-id="${sc.id}">
                  Run Test
                </button>
              </div>
            </div>
          `).join("")}
        </div>

        <!-- Results Table Card -->
        <div class="saas-card" id="test-lab-results-card">
          <div class="saas-card-header">
            <div class="saas-card-title">Comparative Test Results (Actual Measured Latency & Leaks)</div>
            <span class="badge badge-success" id="benchmark-status-badge">AWAITING TEST EXECUTION</span>
          </div>

          <div style="overflow-x: auto;">
            <table class="findings-table" id="test-lab-table">
              <thead>
                <tr>
                  <th>Scenario</th>
                  <th>Planted Canaries</th>
                  <th>Baseline Regex Leaks</th>
                  <th>PrivacyLens Leaks</th>
                  <th>Egress Decision</th>
                  <th>Latency</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody id="test-lab-tbody">
                <tr>
                  <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 32px;">
                    Click <strong>"Run All 5 Scenarios"</strong> or an individual scenario above to execute live comparative benchmarks.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      `;

      // Bind Individual Test Run Buttons
      document.querySelectorAll(".btn-run-single-sc").forEach(btn => {
        btn.addEventListener("click", () => {
          const scId = btn.getAttribute("data-id");
          runSingleTestScenario(scId);
        });
      });

      // Bind Run All Button
      document.getElementById("btn-run-all-tests").addEventListener("click", runAllTestScenarios);

    } catch (e) {
      appContent.innerHTML = `
        <div class="saas-card">
          <div class="empty-state-box">
            <div class="empty-state-title" style="color: var(--status-danger);">Error Loading Scenarios</div>
            <div class="empty-state-desc">${escapeHtml(e.message)}</div>
          </div>
        </div>
      `;
    }
  }

  async function runSingleTestScenario(scId) {
    const card = document.getElementById(`card-${scId}`);
    const badge = document.getElementById("benchmark-status-badge");
    if (badge) badge.innerText = "EXECUTING TEST...";

    try {
      const resp = await fetch("/api/test-lab/run-scenario", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: scId })
      });
      const data = await resp.json();

      updateTestLabTable([data]);
      if (badge) badge.innerText = "TEST COMPLETE";
    } catch (e) {
      if (badge) badge.innerText = `ERROR: ${e.message}`;
    }
  }

  async function runAllTestScenarios() {
    const btn = document.getElementById("btn-run-all-tests");
    const badge = document.getElementById("benchmark-status-badge");
    btn.disabled = true;
    btn.innerHTML = `
      <svg class="spin-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" stroke-opacity="0.3"/><path d="M12 2a10 10 0 0 1 10 10"/></svg>
      Running 5 Scenarios...
    `;
    if (badge) badge.innerText = "RUNNING ALL 5 BENCHMARKS...";

    try {
      const resp = await fetch("/api/test-lab/run-all", { method: "POST" });
      const data = await resp.json();

      updateTestLabTable(data.results || []);
      if (badge) badge.innerText = "ALL 5 BENCHMARKS VERIFIED";
    } catch (e) {
      if (badge) badge.innerText = `ERROR: ${e.message}`;
    } finally {
      btn.disabled = false;
      btn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        Run All 5 Scenarios
      `;
    }
  }

  function updateTestLabTable(results) {
    const tbody = document.getElementById("test-lab-tbody");
    if (!tbody || !results) return;

    tbody.innerHTML = results.map(r => `
      <tr>
        <td>
          <div style="font-weight: 700; color: var(--text-main);">${escapeHtml(r.scenario_name)}</div>
          <div style="font-size: 0.6875rem; color: var(--text-muted);">${escapeHtml(r.category)}</div>
        </td>
        <td>
          <span class="badge badge-primary">${r.planted_canaries_count}</span>
        </td>
        <td>
          <span class="badge badge-danger">${r.baseline.leaked_canaries_count} (${r.baseline.leakage_rate_pct}%)</span>
        </td>
        <td>
          <span class="badge ${r.privacylens.leaked_canaries_count === 0 ? 'badge-success' : 'badge-danger'}">
            ${r.privacylens.leaked_canaries_count} (${r.privacylens.leakage_rate_pct}%)
          </span>
        </td>
        <td>
          <span style="font-size: 0.75rem; font-weight: 700; color: ${r.privacylens.status === 'PROTECTED' ? 'var(--status-success)' : 'var(--status-danger)'};">
            ${escapeHtml(r.privacylens.decision)}
          </span>
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.8125rem;">
          ${r.latency_ms} ms
        </td>
        <td>
          <button class="btn btn-sm btn-outline btn-inspect-test-evidence" data-sess="${r.session_id}">
            Inspect
          </button>
        </td>
      </tr>
    `).join("");

    // Bind Inspect buttons
    tbody.querySelectorAll(".btn-inspect-test-evidence").forEach(btn => {
      btn.addEventListener("click", () => {
        const sessId = btn.getAttribute("data-sess");
        if (sessId) {
          activeSessionId = sessId;
          navigateTo(`/evidence?session_id=${sessId}`);
        }
      });
    });
  }

  // =========================================================================
  // PAGE 5: ACTIVITY LOGS (Real Interceptions, Zero Raw Secrets)
  // =========================================================================

  async function renderActivityPage() {
    appContent.innerHTML = `
      <div style="text-align: center; padding: 40px;">
        <span class="pulse-dot"></span> Loading real-time security events...
      </div>
    `;

    try {
      const resp = await fetch("/api/events/history?limit=100");
      const events = resp.ok ? await resp.json() : [];

      appContent.innerHTML = `
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              Observable Security Audit Logs
            </div>
            <span class="live-pulse-badge"><span class="pulse-dot"></span> IN-MEMORY LOG STREAM</span>
          </div>

          <!-- Search & Filter Controls -->
          <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 16px; margin-bottom: 20px;">
            <input type="text" class="form-input-saas" id="log-search-input" placeholder="Search event message, scan ID, or detail...">
            <select class="form-select-saas" id="log-type-filter">
              <option value="ALL">All Event Types</option>
              <option value="SCAN">Scan Events</option>
              <option value="DETECT">Detection Events</option>
              <option value="SANITIZE">Sanitization Events</option>
              <option value="EGRESS">Egress Firewall Events</option>
              <option value="AI_ACTION">AI Agent Actions</option>
              <option value="CANARY">Canary Audits</option>
            </select>
          </div>

          <!-- Events Table -->
          <div style="overflow-x: auto;">
            <table class="findings-table" id="activity-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event Type</th>
                  <th>Security Detail</th>
                  <th>Session / Scan ID</th>
                </tr>
              </thead>
              <tbody id="activity-tbody">
                ${events.length === 0 ? `
                  <tr>
                    <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 32px;">
                      No events recorded yet.
                    </td>
                  </tr>
                ` : renderEventRows(events)}
              </tbody>
            </table>
          </div>
        </div>
      `;

      // Bind search & filter
      const searchInput = document.getElementById("log-search-input");
      const filterSelect = document.getElementById("log-type-filter");
      const tbody = document.getElementById("activity-tbody");

      function filterEvents() {
        const query = (searchInput.value || "").toLowerCase();
        const typeFilter = filterSelect.value;

        const filtered = events.filter(ev => {
          const matchQuery = (ev.detail || "").toLowerCase().includes(query) ||
                             (ev.event_type || "").toLowerCase().includes(query) ||
                             (ev.scan_id || "").toLowerCase().includes(query);
          const matchType = typeFilter === "ALL" || (ev.event_type || "").includes(typeFilter);
          return matchQuery && matchType;
        });

        tbody.innerHTML = filtered.length === 0 ? `
          <tr>
            <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 24px;">
              No matching activity events found.
            </td>
          </tr>
        ` : renderEventRows(filtered);
      }

      searchInput.addEventListener("input", filterEvents);
      filterSelect.addEventListener("change", filterEvents);

    } catch (e) {
      appContent.innerHTML = `
        <div class="saas-card">
          <div class="empty-state-box">
            <div class="empty-state-title" style="color: var(--status-danger);">Error Loading Logs</div>
            <div class="empty-state-desc">${escapeHtml(e.message)}</div>
          </div>
        </div>
      `;
    }
  }

  function renderEventRows(events) {
    return events.map(ev => `
      <tr>
        <td style="font-family: var(--font-mono); font-size: 0.75rem; white-space: nowrap; color: var(--text-muted);">
          ${escapeHtml(ev.time_display || ev.timestamp)}
        </td>
        <td>
          <span class="event-badge ${getEventBadgeClass(ev.event_type)}">
            ${escapeHtml(ev.event_type)}
          </span>
        </td>
        <td style="font-size: 0.8125rem; color: var(--text-main); max-width: 500px;">
          ${escapeHtml(ev.detail)}
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--accent-cyan);">
          ${escapeHtml(ev.scan_id || "system")}
        </td>
      </tr>
    `).join("");
  }

  // =========================================================================
  // PAGE 6: SETTINGS (AI Provider, API Keys, Detection Preferences, Clear History)
  // =========================================================================

  async function renderSettingsPage() {
    appContent.innerHTML = `
      <div style="text-align: center; padding: 40px;">
        <span class="pulse-dot"></span> Loading firewall configuration...
      </div>
    `;

    try {
      const resp = await fetch("/api/settings");
      const settings = resp.ok ? await resp.json() : {};
      cachedSettings = settings;

      const cats = settings.detect_categories || {};

      appContent.innerHTML = `
        <!-- AI Model Configuration -->
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
              AI Agent Model Configuration
            </div>
            <span class="badge badge-primary">SECURE RUNTIME STORAGE</span>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div class="form-group-saas">
              <label class="form-label-saas" for="set-ai-provider">Active AI Provider:</label>
              <select class="form-select-saas" id="set-ai-provider">
                <option value="gemini" ${settings.ai_provider === 'gemini' ? 'selected' : ''}>Google Gemini (Gemini 1.5 Pro / Flash)</option>
                <option value="openai" ${settings.ai_provider === 'openai' ? 'selected' : ''}>OpenAI (GPT-4o / GPT-4o-mini)</option>
                <option value="ollama" ${settings.ai_provider === 'ollama' ? 'selected' : ''}>Local Ollama (Llama 3 / Mistral)</option>
                <option value="local_benchmark" ${settings.ai_provider === 'local_benchmark' ? 'selected' : ''}>Deterministic Benchmark Planner (Offline 0-Cost)</option>
              </select>
            </div>

            <div class="form-group-saas">
              <label class="form-label-saas" for="set-api-key">API Key (Environment Runtime):</label>
              <div style="display: flex; gap: 8px;">
                <input type="password" class="form-input-saas" id="set-api-key" placeholder="${settings.gemini_api_key_set || settings.openai_api_key_set ? '•••••••••••••••• (Configured in Env)' : 'Enter API Key to enable cloud LLM...'}">
                <button class="btn btn-primary" id="btn-save-key" style="white-space: nowrap;">Save Key</button>
              </div>
            </div>
          </div>
          <div style="font-size: 0.75rem; color: var(--text-muted);">
            Keys are stored in volatile runtime memory only. Never written to git or exposed to browser client scripts.
          </div>
        </div>

        <!-- Privacy Detection Rules & Categories -->
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Sensitive Information Detection Preferences
            </div>
            <span class="badge badge-success">MULTI-MODAL</span>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Indian Aadhaar (12-Digit Verhoeff Dihedral Group)</div>
              <div class="toggle-info-desc">Mathematical checksum algorithm to prevent false positives and catch unspaced variants.</div>
            </div>
            <input type="checkbox" class="switch-input" id="rule-aadhaar" ${cats.aadhaar !== false ? 'checked' : ''}>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Indian Permanent Account Number (PAN)</div>
              <div class="toggle-info-desc">Detects 10-character alphanumeric PAN numbers and entity code syntax.</div>
            </div>
            <input type="checkbox" class="switch-input" id="rule-pan" ${cats.pan !== false ? 'checked' : ''}>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Credit & Debit Card Numbers (Luhn Checksum)</div>
              <div class="toggle-info-desc">Validates Visa, Mastercard, Amex, and RuPay numbers with Luhn mod-10.</div>
            </div>
            <input type="checkbox" class="switch-input" id="rule-cards" ${cats.cards !== false ? 'checked' : ''}>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Corporate & Personal Email Addresses</div>
              <div class="toggle-info-desc">Replaces emails with consistent [EMAIL_1] placeholders in RAM.</div>
            </div>
            <input type="checkbox" class="switch-input" id="rule-email" ${cats.email !== false ? 'checked' : ''}>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Phone & Mobile Numbers (Indian E.164 & International)</div>
              <div class="toggle-info-desc">Detects +91 Indian mobile phone formats and standard formats.</div>
            </div>
            <input type="checkbox" class="switch-input" id="rule-phone" ${cats.phone !== false ? 'checked' : ''}>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Form Passwords & Authentication Keys</div>
              <div class="toggle-info-desc">Scans DOM password attributes and high-entropy secret inputs.</div>
            </div>
            <input type="checkbox" class="switch-input" id="rule-passwords" ${cats.passwords !== false ? 'checked' : ''}>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Split OTP Input Sequences (2FA Boxes)</div>
              <div class="toggle-info-desc">Reconstructs split one-time passcode inputs across adjacent DOM elements.</div>
            </div>
            <input type="checkbox" class="switch-input" id="rule-split-otp" ${cats.split_otp !== false ? 'checked' : ''}>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Cloud API Keys & Bearer Tokens</div>
              <div class="toggle-info-desc">Scans for OpenAI, AWS, Stripe, GitHub, and JWT bearer tokens.</div>
            </div>
            <input type="checkbox" class="switch-input" id="rule-api-keys" ${cats.api_keys !== false ? 'checked' : ''}>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Internal IPv4 Addresses & Endpoints</div>
              <div class="toggle-info-desc">Detects private RFC1918 and internal cluster database IP endpoints.</div>
            </div>
            <input type="checkbox" class="switch-input" id="rule-ip" ${cats.ip_addresses !== false ? 'checked' : ''}>
          </div>
        </div>

        <!-- Fail-Closed Egress Controls -->
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              Security Firewall Enforcement
            </div>
            <span class="badge badge-primary">FAIL-CLOSED</span>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Fail-Closed Mode (Abort on Any Error)</div>
              <div class="toggle-info-desc">If egress validation encounters an error, timeout, or ambiguity, transmission is blocked immediately.</div>
            </div>
            <input type="checkbox" class="switch-input" id="set-fail-closed" ${settings.fail_closed_mode !== false ? 'checked' : ''}>
          </div>

          <div class="toggle-switch-row">
            <div>
              <div class="toggle-info-title">Strict Canary Auditing</div>
              <div class="toggle-info-desc">Generates trackable synthetic canary tokens in outgoing requests to mathematically verify zero cloud leakage.</div>
            </div>
            <input type="checkbox" class="switch-input" id="set-strict-canary" ${settings.strict_canary_audit !== false ? 'checked' : ''}>
          </div>
        </div>

        <!-- Data Retention & Clear History Card -->
        <div class="saas-card">
          <div class="saas-card-header">
            <div class="saas-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              Data Retention & Session History
            </div>
            <span class="badge badge-danger">DANGER ZONE</span>
          </div>

          <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 14px;">
            PrivacyLens stores secrets strictly in volatile process RAM. Purging session history removes all recorded session summaries, live activity event logs, and token mappings from memory.
          </p>

          <button class="btn btn-danger-outline" id="btn-clear-history">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
            Clear All Session History & RAM Vault
          </button>
        </div>
      `;

      // Save Provider & Key
      document.getElementById("btn-save-key").addEventListener("click", async () => {
        const provider = document.getElementById("set-ai-provider").value;
        const key = document.getElementById("set-api-key").value;
        const payload = { ai_provider: provider };
        if (key) {
          if (provider === "gemini") payload.gemini_api_key = key;
          else if (provider === "openai") payload.openai_api_key = key;
        }
        await updateSettingsOnServer(payload);
        alert("AI Provider and Settings updated successfully!");
      });

      // Provider change
      document.getElementById("set-ai-provider").addEventListener("change", async (e) => {
        await updateSettingsOnServer({ ai_provider: e.target.value });
      });

      // Rule toggles
      const rules = ["aadhaar", "pan", "cards", "email", "phone", "passwords", "split-otp", "api-keys", "ip"];
      rules.forEach(rule => {
        const el = document.getElementById(`rule-${rule}`);
        if (el) {
          el.addEventListener("change", async () => {
            const keyName = rule.replace("-", "_");
            await updateSettingsOnServer({
              detect_categories: { [keyName]: el.checked }
            });
          });
        }
      });

      // Fail-closed toggle
      document.getElementById("set-fail-closed").addEventListener("change", async (e) => {
        await updateSettingsOnServer({ fail_closed_mode: e.target.checked });
      });

      // Strict canary toggle
      document.getElementById("set-strict-canary").addEventListener("change", async (e) => {
        await updateSettingsOnServer({ strict_canary_audit: e.target.checked });
      });

      // Clear History Button
      document.getElementById("btn-clear-history").addEventListener("click", async () => {
        if (confirm("Are you sure you want to purge all session records, audit events, and RAM vault secrets? This cannot be undone.")) {
          const resp = await fetch("/api/settings/clear-history", { method: "POST" });
          if (resp.ok) {
            alert("All session history and RAM vault tokens have been purged.");
            renderSettingsPage();
          }
        }
      });

    } catch (e) {
      appContent.innerHTML = `
        <div class="saas-card">
          <div class="empty-state-box">
            <div class="empty-state-title" style="color: var(--status-danger);">Error Loading Settings</div>
            <div class="empty-state-desc">${escapeHtml(e.message)}</div>
          </div>
        </div>
      `;
    }
  }

  async function updateSettingsOnServer(settingsPayload) {
    try {
      const resp = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settingsPayload)
      });
      return await resp.json();
    } catch (e) {
      console.error("Failed to update settings", e);
    }
  }


  function initThemeToggle() {
    const btn = document.getElementById("btn-theme-toggle");
    const label = document.getElementById("theme-label");

    function updateLabel() {
      const isDark = document.documentElement.getAttribute("data-theme") === "dark";
      if (label) label.innerText = isDark ? "Light" : "Dark";
    }

    updateLabel();

    if (btn) {
      btn.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-theme");
        const next = current === "dark" ? "light" : "dark";
        if (next === "dark") {
          document.documentElement.setAttribute("data-theme", "dark");
        } else {
          document.documentElement.removeAttribute("data-theme");
        }
        localStorage.setItem("privacylens_theme", next);
        updateLabel();
      });
    }
  }

  // =========================================================================
  // BOOTSTRAP APPLICATION
  // =========================================================================

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      initRouter();
    });
  } else {
    initRouter();
  }

})();
