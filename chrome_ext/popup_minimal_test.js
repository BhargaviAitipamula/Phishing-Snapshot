// popup_minimal_test.js
document.getElementById("analyzeBtn").addEventListener("click", async () => {
  console.log("[popup] Analyze clicked (minimal test)");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  console.log("[popup] Active tab URL:", tab.url);

  const payload = {
    add_info: "<html><body>test</body></html>",
    screenshot_base64: "",  // placeholder
    url: tab.url
  };

  try {
    console.log("[popup] Sending POST to backend...");
    const resp = await fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    console.log("[popup] POST done, awaiting JSON...");
    const json = await resp.json();
    console.log("[popup] Received JSON:", json);
    document.getElementById("status").textContent = "OK: " + json.message;
    document.getElementById("result").textContent = JSON.stringify(json, null, 2);
  } catch (err) {
    console.error("[popup] POST error:", err);
    document.getElementById("status").textContent = "Error: " + err;
  }
});
