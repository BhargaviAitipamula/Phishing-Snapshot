import os
import json
import base64
import uuid
import hashlib
from flask import Flask, request, jsonify
from MMLLM_GPT import MMLLM_GPT, InputDataset, InputMode  # import model

app = Flask(__name__)

# Initialize GPT model with API key
GPT_MODEL = MMLLM_GPT(
    str_api_key=API_KEY)
# --- LIVE CAPTURE directory inside ../data ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # src folder
LIVE_CAPTURE_DIR = os.path.abspath(os.path.join(BASE_DIR, "../data/live_capture"))
os.makedirs(LIVE_CAPTURE_DIR, exist_ok=True)
print(f"[DEBUG] LIVE_CAPTURE_DIR: {LIVE_CAPTURE_DIR}")


def save_capture(data: dict):
    """Save HTML info + screenshot as live capture folder."""
    url = data.get("url", "unknown_url")
    html_info = data.get("html", {})
    screenshot_b64 = data.get("screenshot", "")

    folder_hash = hashlib.sha256(url.encode()).hexdigest()
    folder_path = os.path.join(LIVE_CAPTURE_DIR, folder_hash)
    os.makedirs(folder_path, exist_ok=True)

    # Save add_info.json
    add_info = {
        "Url": url,
        "html_brand_info": f"title: {html_info.get('title','')}\n"
                           f"meta_description: {html_info.get('meta_description','')}\n"
                           f"favicon: {html_info.get('favicon','Not Found')}\n"
                           f"logo_alt_text: {html_info.get('logo_alt_text','Not Found')}\n"
                           f"footer_text: {html_info.get('footer_text','Not Found')}\n"
                           f"headers_text: {html_info.get('headers_text','Not Found')}\n"
                           f"nav_bar_content: {html_info.get('nav_bar_content','Not Found')}\n"
                           f"paragraphs_text: {html_info.get('paragraphs_text','Not Found')}\n"
                           f"span_text: {html_info.get('span_text','Not Found')}"
    }
    add_info_path = os.path.join(folder_path, "add_info.json")
    with open(add_info_path, "w", encoding="utf-8") as f:
        json.dump(add_info, f, indent=4)

    # Save screenshot
    if screenshot_b64.startswith("data:image"):
        _, screenshot_b64 = screenshot_b64.split(",", 1)
    screenshot_path = os.path.join(folder_path, "screenshot_aft.png")
    with open(screenshot_path, "wb") as f:
        f.write(base64.b64decode(screenshot_b64))

    return folder_path, folder_hash


# @app.route("/analyze", methods=["POST"])
# def analyze():
#     """Handle analyze request from Chrome extension or test."""
#     try:
#         req_data = request.get_json()
#         if not req_data:
#             return jsonify({"error": "No JSON received", "status": "fail"}), 400

#         folder_path, folder_hash = save_capture(req_data)
#         print(f"[DEBUG] Saved live capture at: {folder_path}")

#         # Make model read/write to correct paths
#         GPT_MODEL.str_input_dir_base = os.path.abspath(os.path.join(BASE_DIR, "../data"))
#         GPT_MODEL.str_output_dir_base = os.path.abspath(os.path.join(BASE_DIR, "../output"))
#         os.makedirs(GPT_MODEL.str_output_dir_base, exist_ok=True)

#         # Run Phase 1 and Phase 3 for LiveCapture
#         GPT_MODEL.phase1_brand_identification(InputDataset.LiveCapture)
#         GPT_MODEL.phase3_dns_verification(InputDataset.LiveCapture)

#         # Find Phase3 output
#         phase3_dir = os.path.join(GPT_MODEL.str_output_dir_base, "LiveCapture", "Phase3_GPT", "both")
#         result_jsons = []
#         for root, dirs, files in os.walk(phase3_dir):
#             for file in files:
#                 if file.endswith(".json"):
#                     result_jsons.append(os.path.join(root, file))

#         if not result_jsons:
#             return jsonify({"error": "Phase3 output not found", "status": "fail"}), 500

#         with open(result_jsons[0], "r", encoding="utf-8") as f:
#             phase3_result = json.load(f)

#         response = {
#             "is_phishing": not phase3_result.get("IsLegitimate", False),
#             "confidence_score": phase3_result.get("ConfidenceScore", 0.0),
#             "explanation": phase3_result.get("SupportingEvidence", ""),
#             "saved_folder": folder_path
#         }

#         return jsonify(response)

#     except Exception as e:
#         return jsonify({"error": str(e), "status": "fail"}), 500

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        from MMLLM_GPT import MMLLM_GPT, InputDataset
        gpt_model = MMLLM_GPT("YOUR_API_KEY_HERE")
        gpt_model.phase1_brand_identification(InputDataset.LiveCapture)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "fail", "error": str(e)})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
