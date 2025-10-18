from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Add model directory to path so it can import app.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from app import predict_phishing  # import your model prediction function

app = Flask(__name__)
CORS(app)  # allows Chrome extension requests

@app.route('/predict', methods=['POST'])
def predict():
    try:
        html_file = request.files.get('html')
        screenshot_file = request.files.get('screenshot')

        html_content = html_file.read().decode('utf-8') if html_file else ''
        screenshot_data = screenshot_file.read() if screenshot_file else None

        # Call your model
        result = predict_phishing(html_content, screenshot_data)

        # Expected format from model:
        # {"is_phishing": True/False, "confidence": 0.xx}
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
