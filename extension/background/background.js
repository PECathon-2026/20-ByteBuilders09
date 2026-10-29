// PrivacyLens - Background Service Worker (Manifest V3)

const DEFAULT_BACKEND = "http://127.0.0.1:8000";

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["protectionEnabled", "backendUrl"], (res) => {
    if (res.protectionEnabled === undefined) {
      chrome.storage.local.set({ protectionEnabled: true });
    }
    if (!res.backendUrl) {
      chrome.storage.local.set({ backendUrl: DEFAULT_BACKEND });
    }
  });

  // Set initial badge
  chrome.action.setBadgeBackgroundColor({ color: "#0284c7" });
  chrome.action.setBadgeText({ text: "ON" });
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "updateBadge") {
    const count = request.count;
    if (count > 0) {
      chrome.action.setBadgeText({ text: String(count) });
      chrome.action.setBadgeBackgroundColor({ color: "#f43f5e" }); // red badge when sensitive items found
    } else {
      chrome.action.setBadgeText({ text: "0" });
      chrome.action.setBadgeBackgroundColor({ color: "#10b981" }); // green when 0 findings
    }
    sendResponse({ status: "badge_updated" });
  } else if (request.action === "toggleProtection") {
    const isEnabled = request.enabled;
    chrome.action.setBadgeText({ text: isEnabled ? "ON" : "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: isEnabled ? "#0284c7" : "#64748b" });
    sendResponse({ status: "toggled" });
  }
  return true;
});
