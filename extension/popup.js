const API_BASE = "http://127.0.0.1:8000";


async function postJson(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  
  let data;
  try {
    data = await resp.json();
  } catch (e) {
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} - Could not parse response.`);
    }
    return {};
  }
  
  if (!resp.ok) {
    throw new Error(data.error || data.detail || `HTTP ${resp.status}`);
  }
  return data;
}

document.addEventListener("DOMContentLoaded", () => {
  const analyzeBtn = document.getElementById("analyze-btn");
  const toggleJsonBtn = document.getElementById("toggle-json-btn");
  const copyJsonBtn = document.getElementById("copy-json-btn");

  analyzeBtn.addEventListener("click", handleAnalyzeClick);
  
  toggleJsonBtn.addEventListener("click", () => {
    const raw = document.getElementById("raw-json");
    if (raw.classList.contains("json-hidden")) {
      raw.classList.remove("json-hidden");
      toggleJsonBtn.textContent = "Hide Raw JSON";
    } else {
      raw.classList.add("json-hidden");
      toggleJsonBtn.textContent = "View Raw JSON";
    }
  });

  copyJsonBtn.addEventListener("click", () => {
    const rawText = document.getElementById("raw-json").textContent;
    if (!rawText) return;

    const statusEl = document.getElementById("copy-status");
    const fallbackCopy = (text) => {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        statusEl.textContent = "Copied!";
      } catch (err) {
        statusEl.textContent = "Error";
      }
      document.body.removeChild(ta);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(rawText).then(() => {
        statusEl.textContent = "Copied!";
      }).catch(() => {
        fallbackCopy(rawText);
      });
    } else {
      fallbackCopy(rawText);
    }
    
    setTimeout(() => { statusEl.textContent = ""; }, 2000);
  });
});

function showStatus(msg) {
  document.getElementById("status-area").classList.remove("status-hidden");
  document.getElementById("error-area").classList.add("error-hidden");
  document.getElementById("result-area").classList.add("result-hidden");
  document.getElementById("status-msg").textContent = msg;
}

function showError(msg) {
  document.getElementById("status-area").classList.add("status-hidden");
  document.getElementById("result-area").classList.add("result-hidden");
  const errArea = document.getElementById("error-area");
  errArea.classList.remove("error-hidden");
  document.getElementById("error-text").textContent = msg;
}

function showResults(data, evidenceObj) {
  document.getElementById("status-area").classList.add("status-hidden");
  document.getElementById("error-area").classList.add("error-hidden");
  document.getElementById("result-area").classList.remove("result-hidden");

  // Format UI
  document.getElementById("score-text").textContent = data.score_total;
  
  const badge = document.getElementById("severity-badge");
  badge.textContent = data.severity_label;
  badge.className = "badge " + data.severity_label.toLowerCase();

  const reasonsList = document.getElementById("reasons-list");
  reasonsList.innerHTML = "";
  (data.reasons || []).slice(0, 3).forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsList.appendChild(li);
  });

  const recsList = document.getElementById("recs-list");
  recsList.innerHTML = "";
  (data.recommendations || []).slice(0, 3).forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    recsList.appendChild(li);
  });

  // Extract consent meta from the scan evidence if available
  // The backend might not send evidence back in /analyze response directly, 
  // actually looking at views.py PolicyAnalyzeResponseSerializer, evidence isn't returned directly.
  // Wait, I am sending it in Phase 2 just to populate `/api/scans/ingest` DB payload.
  // We can just use the DOM evidence we fetched in handleAnalyzeClick instead of waiting for API response
  // Or we can modify `evidence` globally. Let's pass evidence to showResults.
  if (evidenceObj && evidenceObj.consent_meta) {
    const consent = evidenceObj.consent_meta;
    let text = "";
    if (consent.banner_detected) {
      const reject = consent.reject_available ? "Yes" : "No";
      const manage = consent.manage_available ? "Yes" : "No";
      const vendor = consent.banner_vendor ? consent.banner_vendor : "-";
      text = `Detected. Reject: ${reject}, Manage: ${manage}, Vendor: ${vendor}`;
    } else {
      text = "Not detected.";
    }
    document.getElementById("consent-status-text").textContent = text;
  }

  document.getElementById("raw-json").textContent = JSON.stringify(data, null, 2);
}

async function handleAnalyzeClick() {
  const btn = document.getElementById("analyze-btn");
  btn.disabled = true;
  showStatus("Gathering site evidence...");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      throw new Error("Cannot determine active tab URL.");
    }

    const urlObj = new URL(tab.url);
    const domain = urlObj.hostname;

    // Extract Cookies
    const cookies = await chrome.cookies.getAll({ domain: domain });
    
    let missingSecure = 0;
    let missingHttpOnly = 0;
    let missingSameSite = 0;

    const cookies_meta = cookies.map(c => {
      if (c.secure === false) missingSecure++;
      if (c.httpOnly === false) missingHttpOnly++;
      if (c.sameSite === "unspecified" || !c.sameSite) missingSameSite++;

      return {
        name: c.name,
        domain: c.domain,
        path: c.path,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: c.sameSite,
        expirationDate: c.expirationDate
      };
    });

    const cookieRiskText = `Cookie risks (${cookies.length} cookies): Secure missing ${missingSecure}, HttpOnly missing ${missingHttpOnly}, SameSite missing ${missingSameSite}`;
    document.getElementById("cookie-risk-text").textContent = cookieRiskText;

    // Extract Storage
    const [{ result: storageCounts }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        return {
          localStorage_key_count: window.localStorage ? window.localStorage.length : 0,
          sessionStorage_key_count: window.sessionStorage ? window.sessionStorage.length : 0
        };
      }
    });

    // Extract Consent Banner info
    const [{ result: consentMeta }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        // Heuristic function runs in page context
        let banner_detected = false;
        let reject_available = null;
        let manage_available = null;
        let banner_vendor = null;

        function isVisible(el) {
          if (!el) return false;
          if (el.offsetParent === null) return false;
          const style = window.getComputedStyle(el);
          if (style.visibility === 'hidden' || style.display === 'none') {
            return false;
          }
          return true;
        }

        // 1. Detect potential banner container
        const bannerSelectors = [
          '[id*="cookie" i]', '[class*="cookie" i]',
          '[id*="consent" i]', '[class*="consent" i]',
          '[id*="gdpr" i]', '[class*="gdpr" i]',
          '[id*="cmp" i]', '[class*="cmp" i]',
          '[id*="onetrust" i]', '[class*="onetrust" i]',
          '[id*="trustarc" i]', '[class*="trustarc" i]',
          '[id*="privacy" i]', '[class*="privacy" i]',
          '[id*="banner" i]', '[class*="banner" i]'
        ];

        let bannerEl = null;
        for (const sel of bannerSelectors) {
          const els = Array.from(document.querySelectorAll(sel));
          const visibleEl = els.find(e => isVisible(e) && e.textContent.length > 20); // must have some text
          if (visibleEl) {
            bannerEl = visibleEl;
            break;
          }
        }

        // 2. Keyword fallback on body text if no container found
        if (!bannerEl) {
          const bodyText = document.body.innerText.toLowerCase();
          const keywords = ["cookies", "cookie", "consent", "privacy preferences"];
          if (keywords.some(kw => bodyText.includes(kw))) {
             // We'll treat the entire body text as having a banner context initially, 
             // but lacking a specific banner element means we'll just parse the document for buttons.
             // We'll set banner_detected to true if we find relevant buttons in step 3.
          }
        } else {
          banner_detected = true;
        }

        // 3. Search for Buttons (Reject / Manage)
        const searchRoot = bannerEl || document;
        const buttons = Array.from(searchRoot.querySelectorAll('button, a, input[type="button"], [role="button"]'));
        
        // Let's also check if we see "accept/allow" to strengthen detection
        let foundAccept = false;

        buttons.forEach(btn => {
          if (!isVisible(btn)) return;
          const text = (btn.textContent || btn.value || '').toLowerCase().trim();
          
          if (text.includes("accept") || text.includes("allow all")) {
             foundAccept = true;
          }
          if (text.includes("reject") || text.includes("decline") || text.includes("do not sell") || text.includes("only necessary") || text.includes("essential only")) {
             reject_available = true;
          }
          if (text.includes("manage") || text.includes("preferences") || text.includes("settings") || text.includes("options")) {
             manage_available = true;
          }
        });

        // If we found accept buttons and keywords but no clear banner container, we'll assume there is one.
        if (!banner_detected && foundAccept) {
          banner_detected = true;
        }

        // Refilter fallback values
        if (!banner_detected) {
          reject_available = null;
          manage_available = null;
        } else {
          // Default to false if banner exists but buttons weren't found
          if (reject_available === null) reject_available = false;
          if (manage_available === null) manage_available = false;
        }

        // 4. Check vendor
        if (banner_detected && bannerEl) {
           const identifier = (bannerEl.id + " " + bannerEl.className).toLowerCase();
           if (identifier.includes("onetrust")) banner_vendor = "onetrust";
           else if (identifier.includes("trustarc")) banner_vendor = "trustarc";
           else if (identifier.includes("quantcast")) banner_vendor = "quantcast";
        }

        // 5. OneTrust specific overrides
        if (banner_detected && banner_vendor === "onetrust") {
            const manageBtn = document.getElementById("onetrust-pc-btn-handler");
            if (manageBtn && isVisible(manageBtn)) {
                manage_available = true;
            }
            const rejectBtn = document.getElementById("onetrust-reject-all-handler");
            if (rejectBtn && isVisible(rejectBtn)) {
                reject_available = true;
            }
            const acceptBtn = document.getElementById("onetrust-accept-btn-handler");
            if (acceptBtn && isVisible(acceptBtn)) {
                banner_detected = true;
            }
        }

        return {
          banner_detected: banner_detected,
          reject_available: reject_available,
          manage_available: manage_available,
          banner_vendor: banner_vendor
        };
      }
    });

    const evidence = {
      third_party_domains: [], // Placeholder for MVP
      cookies_meta: cookies_meta,
      storage_meta: storageCounts,
      consent_meta: consentMeta,
      headers_meta: { is_https: tab.url.startsWith("https") }
    };

    // 1. Ingest
    showStatus("Ingesting scan data...");
    const ingestData = await postJson(`${API_BASE}/api/scans/ingest`, {
      domain: domain,
      url: tab.url,
      evidence: evidence
    });
    const scanId = ingestData.scan_id;

    // 2. Analyze
    showStatus("Analyzing privacy policies (this may take a moment)...");
    const analyzePayload = { scan_id: scanId };
    
    const analyzeData = await postJson(`${API_BASE}/api/policies/analyze`, analyzePayload);
    showResults(analyzeData, evidence);

  } catch (error) {
    console.error(error);
    showError(error.message);
  } finally {
    btn.disabled = false;
  }
}
