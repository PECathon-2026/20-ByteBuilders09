// PrivacyLens - Content Script
// Safely extracts page structure and form inputs when user requests a scan.
// Never submits forms or modifies pages without user knowledge.

function extractPageData() {
  const title = document.title || "";
  const url = window.location.href || "";
  const fullText = document.body ? document.body.innerText : "";

  // Identify sensitive form inputs
  const formElements = Array.from(document.querySelectorAll("input, textarea, select"));
  const inputFindings = [];

  formElements.forEach((el, index) => {
    const type = (el.type || "").toLowerCase();
    const autocomplete = (el.getAttribute("autocomplete") || "").toLowerCase();
    const name = (el.getAttribute("name") || "").toLowerCase();
    const id = (el.id || "").toLowerCase();
    const val = el.value || "";

    // 1. Password input detection
    if (type === "password") {
      inputFindings.push({
        selector: el.id ? `#${el.id}` : `input[type=password]:nth-of-type(${index + 1})`,
        type: "PASSWORD",
        confidence: 0.99,
        reason: "DOM input[type=password]"
      });
    }

    // 2. Sensitive autocomplete detection
    if (autocomplete.includes("cc-") || autocomplete.includes("password") || autocomplete.includes("one-time-code")) {
      inputFindings.push({
        selector: el.id ? `#${el.id}` : `input[autocomplete=${autocomplete}]`,
        type: autocomplete.includes("cc") ? "CARD" : "CREDENTIAL",
        confidence: 0.95,
        reason: `DOM autocomplete='${autocomplete}' attribute`
      });
    }

    // 3. Name or id context hints
    const context = `${name} ${id}`;
    if (/cvv|cvc|security.code/.test(context)) {
      inputFindings.push({
        selector: el.id ? `#${el.id}` : `input[name=${name}]`,
        type: "CVV",
        confidence: 0.94,
        reason: "Field identifier matches CVV pattern"
      });
    }
  });

  return {
    title: title,
    url: url,
    text: fullText.slice(0, 50000), // bounded buffer
    inputFindings: inputFindings
  };
}

// Visual Privacy Highlighter (local visual aid only)
function applyVisualHighlights(selectors) {
  selectors.forEach((sel) => {
    try {
      const el = document.querySelector(sel);
      if (el) {
        el.style.outline = "2px dashed #f43f5e";
        el.style.backgroundColor = "rgba(244, 63, 94, 0.08)";
        el.setAttribute("title", "PrivacyLens: Sensitive Field Protected");
      }
    } catch (e) {
      // Ignore invalid selectors safely
    }
  });
}

// Message Listener
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getPageContent") {
    const pageData = extractPageData();
    sendResponse({ status: "success", data: pageData });
  } else if (request.action === "highlightFields") {
    applyVisualHighlights(request.selectors || []);
    sendResponse({ status: "highlighted" });
  }
  return true;
});
