// // popup.js - runs when popup.html loads
// const statusEl = document.getElementById("status");
// const resultEl = document.getElementById("result");

// // Send a message to background to capture and analyze
// function startAnalysis() {
//   statusEl.textContent = "Analyzing page... (capturing screenshot & HTML)";
//   resultEl.innerHTML = "";

//   chrome.runtime.sendMessage({ type: "capture_and_analyze" }, (resp) => {
//     if (!resp) {
//       statusEl.textContent = "Error: no response from background";
//       return;
//     }
//     if (resp.status === "error") {
//       statusEl.textContent = "Error during capture: " + resp.error;
//       resultEl.innerHTML = `<pre>${resp.error}</pre>`;
//       return;
//     }

//     const payload = resp.data;
//     if (payload.status === "fail") {
//       statusEl.textContent = "Model error";
//       resultEl.innerHTML = `<pre>${payload.error || JSON.stringify(payload)}</pre>`;
//       return;
//     }

//     // Successful response object from your Flask / model backend
//     statusEl.textContent = "Done.";
//     const isPhishing = payload.is_phishing ? "⚠️ Phishing Detected" : "✅ Likely Legitimate";
//     const color = payload.is_phishing ? "warn" : "ok";

//     resultEl.innerHTML = `
//       <p><span class="${color}">${isPhishing}</span></p>
//       <p><b>Brand:</b> ${payload.brand || "Unknown"}</p>
//       <p><b>Confidence:</b> ${payload.confidence}</p>
//       <p><b>Explanation:</b></p>
//       <pre>${payload.explanation || "No explanation returned."}</pre>
//       <p style="font-size:11px;color:#666"><b>Suspect:</b> ${payload.suspect_domain || ""} &nbsp; <b>Legit:</b> ${payload.legit_domain || ""}</p>
//     `;
//   });
// }

// // Auto-start when popup loads
// startAnalysis();


// // console.log("[Popup] sending ping...");
// // chrome.runtime.sendMessage({ type: "ping" }, (resp) => {
// //   console.log("[Popup] response:", resp);
// //   if (!resp) document.body.innerHTML += "<p style='color:red'>No response from background</p>";
// //   else document.body.innerHTML += `<p style='color:green'>Background replied: ${resp.reply}</p>`;
// // });

document.addEventListener("DOMContentLoaded", async () => {
  const status = document.getElementById("status");
  status.innerText = "Analyzing page... (capturing screenshot & HTML)";
  console.log("[Popup] Starting capture...");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // Capture screenshot
    const screenshotRaw = await chrome.tabs.captureVisibleTab(null, { format: "png" });

    // Compress it using canvas in popup context (DOM allowed)
    const screenshot = await compressImage(screenshotRaw);
    console.log("[Popup] Screenshot captured & compressed");

    // Extract simplified HTML info
    const [{ result: html_summary }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const title = document.title;
        const metas = Array.from(document.querySelectorAll("meta"))
          .map(m => `${m.name || m.property || "meta"}:${m.content || ""}`)
          .slice(0, 30)
          .join("\n");
        const links = Array.from(document.querySelectorAll("a"))
          .map(a => a.href)
          .filter(Boolean)
          .slice(0, 50)
          .join("\n");
        const forms = Array.from(document.querySelectorAll("form"))
          .map(f => f.action)
          .filter(Boolean)
          .slice(0, 10)
          .join("\n");
        return `Title: ${title}\n\nMeta:\n${metas}\n\nLinks:\n${links}\n\nForms:\n${forms}`;
      },
    });

    console.log("[Popup] HTML summary captured");

    // Send to background to handle Flask API call
    chrome.runtime.sendMessage(
      {
        type: "analyze_page",
        url: tab.url,
        html: html_summary,
        screenshot: screenshot,
      },
      (resp) => {
        console.log("[Popup] Got response:", resp);
        if (!resp) {
          status.innerText = "Error: no response from background";
          return;
        }
        if (resp.error) {
          status.innerText = `Error: ${resp.error}`;
          return;
        }

        const { is_phishing, confidence_score, explanation } = resp;
        status.innerHTML = `
          <h3>Phishing Detector Result</h3>
          <p><b>Phishing:</b> ${is_phishing ? "⚠️ Yes" : "✅ No"}</p>
          <p><b>Confidence:</b> ${confidence_score?.toFixed(2) ?? "N/A"} / 10</p>
          <p><b>Explanation:</b> ${explanation || "No explanation available"}</p>
        `;
      }
    );
  } catch (err) {
    console.error("[Popup] Error during capture:", err);
    status.innerText = `Error: ${err.message}`;
  }
});

// compressImage uses DOM canvas (works only in popup, not background)
function compressImage(base64Image, maxWidth = 400) {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      const scale = maxWidth / img.width;
      canvas.width = maxWidth;
      canvas.height = img.height * scale;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      resolve(canvas.toDataURL("image/png", 0.7));
    };
    img.src = base64Image;
  });
}

