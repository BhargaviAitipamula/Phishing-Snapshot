// // background.js - fixed version

// chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
//   if (msg && msg.type === "capture_and_analyze") {
//     (async () => {
//       try {
//         // 1️⃣ Get the active tab
//         const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
//         if (!tab) throw new Error("No active tab found.");

//         // 2️⃣ Capture screenshot as Base64 data URL
//         const screenshotDataUrl = await new Promise((resolve, reject) => {
//           chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" }, (dataUrl) => {
//             if (chrome.runtime.lastError) return reject(chrome.runtime.lastError.message);
//             if (!dataUrl) return reject("Screenshot capture returned null/undefined.");
//             resolve(dataUrl);
//           });
//         });

//         // 3️⃣ Extract full HTML content of the page
//         const [result] = await chrome.scripting.executeScript({
//           target: { tabId: tab.id },
//           func: () => document.documentElement.outerHTML
//         });
//         const htmlContent = result?.result || "";

//         // 4️⃣ Send to local Flask backend
//         const resp = await fetch("http://127.0.0.1:5000/analyze", {
//           method: "POST",
//           headers: { "Content-Type": "application/json" },
//           body: JSON.stringify({
//             url: tab.url,
//             html: htmlContent,
//             screenshot: screenshotDataUrl
//           })
//         });

//         const data = await resp.json();
//         console.log("[PhishingDetector] Backend response:", data);

//         // 5️⃣ Send back to popup
//         sendResponse({ status: "ok", data });
//       } catch (err) {
//         console.error("[PhishingDetector] Error:", err);
//         sendResponse({ status: "error", error: String(err) });
//       }
//     })();

//     // ✅ Tell Chrome this listener will send response asynchronously
//     return true;
//   }
// });


// console.log("[PD] Service worker started");

// chrome.runtime.onInstalled.addListener(() => {
//   console.log("[PD] Extension installed or updated");
// });

// chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
//   console.log("[PD] Message received:", msg);
//   sendResponse({ reply: "pong" });
// });
console.log("[PD] Service worker started");

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log("[PD] Message received:", msg);

  if (msg.type === "analyze_page") {
    analyzePage(msg, sendResponse);
    return true;
  }
});

async function analyzePage(msg, sendResponse) {
  try {
    console.log("[PD] Sending to Flask backend...");
    const res = await fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: msg.url,
        html: msg.html,
        screenshot: msg.screenshot,
      }),
    });

    const data = await res.json();
    console.log("[PD] API response:", data);
    sendResponse(data);
  } catch (err) {
    console.error("[PD] Error in analyzePage:", err);
    sendResponse({ error: err.message });
  }
}
