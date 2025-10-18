// (async function() {
//   try {
//     if (typeof html2canvas === "undefined") {
//       console.error("html2canvas not loaded");
//       return;
//     }

//     // Take screenshot of full page
//     const canvas = await html2canvas(document.documentElement, { useCORS: true, allowTaint: false });
//     const screenshotBase64 = canvas.toDataURL("image/png");

//     // Get page HTML
//     const pageHtml = document.documentElement.outerHTML;

//     // Send the data back to the extension
//     window.postMessage({
//       direction: "FROM_PAGE_TO_EXTENSION",
//       screenshot_base64: screenshotBase64,
//       add_info: pageHtml,
//       url: location.href
//     }, "*");
//   } catch (err) {
//     console.error("Capture error:", err);
//     window.postMessage({ direction: "FROM_PAGE_TO_EXTENSION", error: err.toString() }, "*");
//   }
// })();

(async function() {
  try {
    console.log("[inject_capture] script started");
    if (typeof html2canvas === "undefined") {
      console.warn("[inject_capture] html2canvas is not loaded in page context");
      // still try to notify extension that html2canvas not available
      window.postMessage({ direction: "FROM_PAGE_TO_EXTENSION", error: "html2canvas_not_loaded" }, "*");
      return;
    }

    // small wait to allow page resources to settle
    await new Promise(r => setTimeout(r, 300));

    console.log("[inject_capture] calling html2canvas...");
    const canvas = await html2canvas(document.documentElement, { useCORS: true, allowTaint: false, scale: 1 });
    console.log("[inject_capture] canvas created");

    const screenshotBase64 = canvas.toDataURL("image/png");
    const pageHtml = document.documentElement.outerHTML;

    console.log("[inject_capture] posting data to extension (via window.postMessage). sizes:", pageHtml.length, screenshotBase64.length);
    window.postMessage({
      direction: "FROM_PAGE_TO_EXTENSION",
      screenshot_base64: screenshotBase64,
      add_info: pageHtml,
      url: location.href
    }, "*");
  } catch (err) {
    console.error("[inject_capture] error:", err);
    window.postMessage({ direction: "FROM_PAGE_TO_EXTENSION", error: err.toString() }, "*");
  }
})();
