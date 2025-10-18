const resultDiv = document.getElementById('result');
const checkBtn = document.getElementById('checkBtn');

function setExtensionIcon(path) {
  chrome.runtime.sendMessage({ type: "setIcon", iconPath: path });
}

checkBtn.addEventListener('click', async () => {
  resultDiv.textContent = 'Analyzing page...';
  setExtensionIcon('icons/icons.png'); // loading icon

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  // get HTML
  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => document.documentElement.outerHTML,
  }, async (results) => {
    const htmlContent = results[0].result;

    // capture screenshot
    chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" }, async (screenshotUrl) => {
      try {
        // convert screenshot to base64 string
        const response = await fetch(screenshotUrl);
        const blob = await response.blob();
        const reader = new FileReader();
        reader.onloadend = async () => {
          const screenshotBase64 = reader.result; // this includes "data:image/png;base64,..."

          // send JSON payload
          const res = await fetch('http://127.0.0.1:5000/analyze', {
            method: 'POST',
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              url: tab.url,
              add_info: htmlContent,
              screenshot_base64: screenshotBase64
            })
          });

          let data;
          try {
            data = await res.json();
          } catch (err) {
            const text = await res.text();
            resultDiv.textContent = "Error parsing JSON from backend:\n" + text;
            setExtensionIcon('icons/icons.png');
            return;
          }

          if (data.error) {
            resultDiv.textContent = 'Error: ' + data.error;
            setExtensionIcon('icons/icons.png');
          } else {
            resultDiv.innerHTML = `
              <strong>Phishing:</strong> ${data.is_phishing ? '🟥 Yes' : '🟩 No'}<br>
              <strong>Confidence:</strong> ${(data.confidence * 100).toFixed(2)}%
            `;

            setExtensionIcon(data.is_phishing ? 'icons/iconReed.png' : 'icons/iconGreen.png');
          }
        };
        reader.readAsDataURL(blob);
      } catch (err) {
        resultDiv.textContent = 'Error: ' + err.message;
        setExtensionIcon('icons/icons.png');
      }
    });
  });
});
