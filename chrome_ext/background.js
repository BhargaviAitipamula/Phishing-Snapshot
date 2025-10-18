// background.js (MV3 service worker)

chrome.runtime.onInstalled.addListener(() => {
  // set default/icons icon on install
  chrome.action.setIcon({ path: {
    "16": "icons/icons.png",
    "48": "icons/icons.png",
    "128": "icons/icons.png"
  }});
  console.log("Phishing Detector installed — starting icon set.");
});

// Listen for icon-change requests from popup or other parts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "setIcon" && message?.iconPath) {
    // Accept either string path or map of sizes
    let path = message.iconPath;
    // If user sent a single string, allow that too:
    if (typeof path === "string") {
      path = { "16": path, "48": path, "128": path };
    }
    chrome.action.setIcon({ path })
      .then(() => sendResponse({ ok: true }))
      .catch(err => sendResponse({ ok: false, error: String(err) }));
    // Return true to indicate we will respond asynchronously
    return true;
  }
});
