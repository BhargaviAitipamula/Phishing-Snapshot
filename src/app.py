
from flask import Flask, request, jsonify
from MMLLM_GPT import MMLLM_GPT
from MMLLM_Common import InputDataset
import base64
import os


app = Flask(__name__)

# Initialize your model
MODEL = MMLLM_GPT(str_api_key)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url")
    html = data.get("html")
    screenshot = data.get("screenshot")


    if len(html) > 15000:
        html = html[:15000] + "...[TRIMMED]"
    # Decode screenshot
    image_data = screenshot.split(",")[1]
    screenshot_bytes = base64.b64decode(image_data)
    os.makedirs("live_capture", exist_ok=True)
    ss_path = "live_capture/screenshot.png"
    with open(ss_path, "wb") as f:
        f.write(screenshot_bytes)
    html_path = "live_capture/add_info.json"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # Run Phase 1 + Phase 3 (customized for live mode)
    result = MODEL.phase1_and_phase2_live(ss_path, html, url)

    return jsonify(result)

if __name__ == "__main__":
    app.run(port=5000, debug=True)
