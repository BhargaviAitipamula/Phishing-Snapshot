document.addEventListener("DOMContentLoaded", async () => {
  const status = document.getElementById("status");
  status.innerText = "Analyzing page... (capturing screenshot & HTML)";
  console.log("[Popup] Starting capture...");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // --- Capture screenshot ---
    const screenshotRaw = await chrome.tabs.captureVisibleTab(null, { format: "png" });

    // Compress image before sending
    const screenshot = await compressImage(screenshotRaw);
    console.log("[Popup] Screenshot captured & compressed");

    // --- Extract simplified HTML info ---
    const [{ result: html_summary }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const title = document.title;
        const metas = Array.from(document.querySelectorAll("meta"))
          .map(m => `${m.name || m.property || "meta"}: ${m.content || ""}`)
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

    // --- Send to background for Flask API call ---
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
          status.innerText = "Error: No response from background script.";
          return;
        }
        if (resp.error) {
          status.innerText = `Error: ${resp.error}`;
          return;
        }

        const {
          is_phishing,
          confidence,
          confidence_score,
          explanation,
          ssl_details
        } = resp;

        const confValue = confidence ?? confidence_score ?? "N/A";

        // --- Build SSL info section ---
        let sslSection = "";
        if (ssl_details) {
          if (ssl_details.SSL_Valid) {
            sslSection = `
              <div style="margin-top:10px; border-top:1px solid #ccc; padding-top:8px;">
                <b>🔒 SSL Certificate Details:</b><br>
                Issuer: ${ssl_details.SSL_Issuer || "Unknown"}<br>
                Common Name: ${ssl_details.SSL_CommonName || "N/A"}<br>
                Valid From: ${ssl_details.SSL_NotBefore || "N/A"}<br>
                Valid Until: ${ssl_details.SSL_NotAfter || "N/A"}<br>
                Certificate Age: ${ssl_details.SSL_AgeDays || "N/A"} days
              </div>`;
          } else {
            sslSection = `
              <div style="margin-top:10px; border-top:1px solid #ccc; padding-top:8px;">
                <b>⚠️ SSL Certificate Error:</b> ${ssl_details.Error || "Unavailable"}
              </div>`;
          }
        }

        // --- Display result on popup ---
        status.innerHTML = `
          <h3 style="margin-bottom:6px;">Phishing Detector Result</h3>
          <p><b>Phishing:</b> ${is_phishing ? "⚠️ Yes" : "✅ No"}</p>
          <p><b>Confidence:</b> ${confValue.toFixed ? confValue.toFixed(2) : confValue} / 10</p>
          <p><b>Explanation:</b> ${explanation || "No explanation available."}</p>
          ${sslSection}
        `;
      }
    );
  } catch (err) {
    console.error("[Popup] Error during capture:", err);
    status.innerText = `Error: ${err.message}`;
  }
});

// --- Helper: Compress screenshot image before sending ---
async function compressImage(dataUrl, maxWidth = 640, maxHeight = 480, quality = 0.7) {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      let { width, height } = img;

      // Maintain aspect ratio
      if (width > height) {
        if (width > maxWidth) {
          height = Math.round((height *= maxWidth / width));
          width = maxWidth;
        }
      } else {
        if (height > maxHeight) {
          width = Math.round((width *= maxHeight / height));
          height = maxHeight;
        }
      }

      canvas.width = width;
      canvas.height = height;

      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0, width, height);
      resolve(canvas.toDataURL("image/jpeg", quality).split(",")[1]); // Return base64
    };
    img.src = dataUrl;
  });
}

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
