PHISHING SNAPSHOT: Multimodal AI-Based Phishing Detection Framework
1. Project Overview

Phishing Snapshot is an AI-driven cybersecurity framework that detects phishing webpages by combining visual, textual, and domain-level intelligence in real time.
The system uses multimodal GPT-4o-mini, DNS/WHOIS analysis, and a Chrome extension interface to recognize brands, validate legitimacy, and generate human-understandable explanations for each decision.

Traditional anti-phishing tools depend on URL blacklists, heuristic filters, or rule-based systems, which often fail against AI-generated or visually deceptive phishing websites.
Our approach provides an adaptive, explainable, and real-time detection mechanism that analyzes both the page layout (image) and HTML semantics (text) to make confident predictions.

2. Motivation
Modern phishing attacks are not limited to suspicious URLs — they now use:
Visually cloned websites (brand spoofing)
AI-generated fake login portals
Trusted SSL certificates on malicious domains
Redirect chains between emails and webpages
Existing detectors often misclassify such pages because:
They rely solely on URL/domain lists.
They ignore the visual identity of brands.
They lack reasoning or transparency in their decisions.
Hence, Phishing Snapshot introduces a multimodal reasoning pipeline:
🔹 GPT-4o-mini for semantic + visual understanding
🔹 WHOIS & DNS checks for technical legitimacy
🔹 Chrome Extension for real-time end-user protection

3. Tools & Requirements
Component	Tools / Framework
Dataset	Custom JSON + webpage screenshots
AI Model	OpenAI GPT-4o-mini (Multimodal reasoning)
DNS/WHOIS Verification	whois, dnspython
SSL/TLS Verification (Future)	ssl, socket, cryptography
Email Linkage (Future)	email, re, urllib, tldextract
Backend API	Flask
Frontend Extension	HTML, JavaScript, html2canvas
Communication	REST API + CORS
Data Serialization	JSON
Environment	Python 3.10+, CUDA-enabled PyTorch

4. System Architecture
The architecture is divided into three main AI-driven phases and one frontend interaction layer.
Frontend: Chrome Extension
  Captures:
    Full webpage HTML
    Screenshot (via html2canvas)
  Sends all data to the Flask backend as a structured JSON payload.
Displays final results:
  Brand identified
  Confidence score
  Legitimacy verdict
  Supporting explanation

Phase 1 – Brand Identification
  Input: Screenshot + HTML
  Model: GPT-4o-mini
  Process:
    GPT analyzes visual content (logo, layout, design).
    Extracts text from HTML to understand brand, product, and call-to-action.
    Returns structured JSON:
    {
        "Folder Hash": "03d4ef743a89692c649478a59201ff13700524390c22111e403b31629df5be59",
        "Brand": "12 Volt Does It",
        "Has_Credentials": "Yes",
        "Has_Call_To_Actions": "Yes",
        "List of Credentials fields": "email, username, password",
        "List of Call-To-Actions": "Register Today, Login",
        "Confidence Score": "9.00",
        "Supporting Evidence": "Identified based on matching logo and textual cues."
    }

Phase 2 – DNS & WHOIS Verification
  Input: Brand name + URL (from Phase 1)
  Modules Used: whois, dnspython
  Process:
  Extracts suspect domain and official brand domain.
  Compares:
  Registrar consistency
  Nameserver overlap
  Domain age and hierarchy
  GPT-4o-mini explains the reasoning.
  Output Example:
    {
      "Brand": "12voltdoesit",
      "Hash": "03d4ef743a89692c649478a59201ff13700524390c22111e403b31629df5be59",
      "SuspectDomain": "12voltdoesit.com",
      "LegitDomain": "12voltdoesit.com",
      "IsLegitimate": true,
      "Info": "Same domain or subdomain",
      "ConfidenceScore": 10.0,
      "SupportingEvidence": "Registrar and DNS data confirm identical domains."
    }
    
Phase 3 – Real-Time Integration
Location: Chrome Extension → Flask API
Workflow:
  User clicks “Analyze Page.”
  Screenshot + HTML → Flask → MMLLM_GPT.phase4_live_verification()
  GPT and DNS layers execute sequentially.
  Result JSON stored in /output/Phase3_GPT/hash.json
  Chrome extension reads and displays results with confidence and reasoning.

🧾 5. Dataset Overview
Dataset Type	Description	Example Brands
Multimodal JSON Dataset	Structured HTML and screenshot pairs for brand identification	Apple, PayPal, Tesla, Netflix
Phishing Case Study Dataset	URLs, WHOIS, and HTML attributes	Benign & malicious websites

6. Evaluation Metrics
Metric	Purpose	Model/Phase	Result
Precision	Domain legitimacy	DNS/WHOIS + GPT	96%
Recall	Brand recognition	GPT-4o-mini	92%
F1-Score	Overall phase integration	All Phases	94%
Inference Time	Live detection speed	Extension + API	~6.4 sec/page

7. Key Strengths
✅ Multimodal Analysis (Visual + Text + Domain)
✅ Real-Time Chrome Integration
✅ Explainable AI Decisions (JSON with rationale)
✅ DNS + WHOIS + GPT synergy
✅ Scalable Flask backend for deployment
✅ Adaptable to new phishing trends and zero-day attacks

🚀 8. Setup Instructions
Step 1 — Clone Repository
git clone https://github.com/BhargaviAitipamula/Phishing-Snapshot.git
cd Phishing-Snapshot/src
Step 2 — Install Dependencies
pip install -r requirements.txt
Step 3 — Configure API Key
In MMLLM_main.py:
gpt_exp = MMLLM_GPT("your_openai_api_key")
Step 4 — Run Backend
python MMLLM_main.py
Step 5 — Load Chrome Extension
Open chrome://extensions
Enable Developer mode
Click Load Unpacked → select /extension folder
Click Analyze Page to test phishing detection
🧭 9. Usage Guide
Navigate to any site (e.g., paypal-login.securepage.net).
Click the extension button → data captured.
GPT identifies “PayPal” brand.
DNS/WHOIS finds mismatch between domains.
Extension popup shows:
Brand: PayPal
Confidence: 9.2
Status: 🚨 Phishing detected
Reason: Domain mismatch + fake SSL
10. Future Enhancements
  1. Flexible Chrome Extension
      Allow users to choose analysis mode:
      Only HTML
      Only Screenshot
      Both (Multimodal)
   2. SSL/TLS Certificate Analysis
      Integrate certificate validation logic:
      Verify issuer trust, domain binding, certificate age, and signature chain.
      Flag new or mismatched certificates.
   3. Email-to-Webpage Phishing Linkage
      Parse phishing emails.
      Extract hyperlinks.
      Map them to landing pages.
      Trace attacker campaign chains for complete phishing trail visibility.
11. Repository Structure
Phishing-Snapshot/
│
├── data/
│   ├── live_capture/
│   ├── MMLLM_Phishing/
│   └── top-1m.csv
│
├── output/
│   ├── Phase1_GPT/
│   ├── Phase2_GPT/
│   └── Phase3_GPT/
│
├── src/
│   ├── MMLLM_GPT.py
│   ├── MMLLM_main.py
│   ├── MMLLM_Common.py
│   └── app.py
│
├── extension/
│   ├── popup.html
│   ├── popup.js
│   └── manifest.json
│
│
└── README.md

12. Demo Video
https://drive.google.com/file/d/1-0TTp5YSeP456PNynipdYOBRUT7q6YwM/view?usp=sharing
