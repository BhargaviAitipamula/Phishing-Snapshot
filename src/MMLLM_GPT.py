import json
import glob
import os
from tqdm import tqdm
from MMLLM_Common import *
from openai import OpenAI
from urllib.parse import urlparse
import whois
import dns.resolver

# --- Helpers ---
def _debug(msg: str):
    print(f"[DEBUG] {msg}", flush=True)

def _extract_domain_from_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    host = host.split("@")[-1].split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host

def _whois_info(domain: str):
    registrar, nameservers = None, set()
    try:
        w = whois.whois(domain)
        reg = getattr(w, "registrar", None)
        if isinstance(reg, (list, set, tuple)): reg = next(iter(reg), None)
        registrar = str(reg).strip().lower() if reg else None
        ns_field = getattr(w, "name_servers", None)
        if ns_field:
            if isinstance(ns_field, str): nameservers.add(ns_field.lower())
            else: nameservers.update([str(x).lower() for x in ns_field if x])
    except Exception as e:
        _debug(f"WHOIS error {domain}: {e}")
    if not nameservers:
        try:
            answers = dns.resolver.resolve(domain, "NS", lifetime=5.0)
            for r in answers: nameservers.add(r.to_text().rstrip(".").lower())
        except Exception as e:
            _debug(f"DNS NS resolve error {domain}: {e}")
    return registrar, nameservers

def _dns_check_pair(suspect: str, legit: str):
    if not suspect or not legit: return False, "Missing domain(s)"
    if suspect == legit or suspect.endswith("." + legit): 
        return True, "Same domain or subdomain"
    s_reg, s_ns = _whois_info(suspect)
    l_reg, l_ns = _whois_info(legit)
    if s_reg and l_reg:
        if s_reg == l_reg: return True, f"Registrar match: {s_reg}"
        return False, f"Registrar mismatch: {s_reg} vs {l_reg}"
    if s_ns and l_ns:
        inter = s_ns.intersection(l_ns)
        if inter: return True, f"Nameserver overlap: {sorted(inter)}"
        return False, "Nameserver mismatch"
    return False, "Insufficient DNS/WHOIS signals"

def _get_ssl_details(self, domain: str, timeout: float = 5.0):
    """
    Retrieve SSL/TLS certificate details including issuer, common name, and certificate age.
    Returns a dict with SSL info. No external API required.
    """
    import ssl, socket, datetime
    ssl_info = {
        "SSL_Valid": False,
        "SSL_Issuer": None,
        "SSL_CommonName": None,
        "SSL_NotBefore": None,
        "SSL_NotAfter": None,
        "SSL_AgeDays": None,
        "Error": None
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(timeout)
            s.connect((domain, 443))
            cert = s.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {}
        issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}

        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        ssl_info.update({
            "SSL_Valid": True,
            "SSL_Issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "SSL_CommonName": subject.get("commonName"),
            "SSL_NotBefore": not_before,
            "SSL_NotAfter": not_after
        })

        # Calculate certificate age in days
        try:
            nb = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            ssl_info["SSL_AgeDays"] = (now - nb).days
        except Exception:
            ssl_info["SSL_AgeDays"] = None

    except Exception as e:
        ssl_info["Error"] = str(e)

    return ssl_info

class MMLLM_GPT:
    def __init__(self, str_api_key:str):
        self.str_api_key = str_api_key
        self.dict_phase1_system_msg = {}
        self.dict_phase1_res_format = {}
        self.str_model = "gpt-4o-mini"
        self.client = OpenAI(api_key=self.str_api_key)
        self.str_input_dir_base = "../data"
        self.str_output_dir_base = "../output"  
        self.tranco_set = set()
        tranco_file=r"C:\Users\DELL\Desktop\Phishing\data\top-1m.csv"
        if os.path.exists(tranco_file):
            with open(tranco_file, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split(",")
                    if len(parts) == 2:
                        self.tranco_set.add(parts[1].lower())
            _debug(f"Loaded {len(self.tranco_set)} domains from Tranco list")
 

    def load_prompt_text(self, input_mode: InputMode):
        str_phase1_prompt_path = dict_system_prompt_path.get(input_mode)
        assert str_phase1_prompt_path, f"Unknown Input mode {input_mode}"

        with open(str_phase1_prompt_path, encoding='utf-8') as f:
            str_phase1_system_prompt = f.read()
            self.dict_phase1_system_msg = {
                "role": "system",
                "content": [{"type": "text", "text": str_phase1_system_prompt}],
            }

        str_phase1_response_prompt_path = dict_response_prompt_path.get(input_mode)
        assert str_phase1_response_prompt_path, f"Unknown Input mode {input_mode}"

        with open(str_phase1_response_prompt_path, encoding='utf-8') as f:
            str_res_format = f.read()
            self.dict_phase1_res_format = {
                "role": "user",
                "content": [{"type": "text", "text": str_res_format}],
            }

    def create_identification_prompt(self, input_mode: InputMode, encoded_image, html_content):
        user_msg = {"role": "user", "content": []}
        if input_mode == InputMode.SS:
            user_msg["content"].append({"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{encoded_image}"}})
        elif input_mode == InputMode.HTML:
            user_msg["content"].append({"type": "text", "text": f"Here is the html information: {html_content}"})
        elif input_mode == InputMode.BOTH:
            user_msg["content"].append({"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{encoded_image}"}})
            user_msg["content"].append({"type": "text", "text": f"Here is the html information: {html_content}"})
        return [self.dict_phase1_system_msg, user_msg, self.dict_phase1_res_format]


    def query(self, messages):
        return self.client.chat.completions.create(
            model=self.str_model,
            messages=messages,
            max_tokens=4096
        )

    def phase1_brand_identification(self, input_dataset: InputDataset):
        dataset_name = input_dataset.value
        
        # Debug: Check what dataset_name actually is
        print(f"[DEBUG] dataset_name = '{dataset_name}'")
        print(f"[DEBUG] input_dataset = {input_dataset}")
        
        # Debug: Check the input_dir_base
        print(f"[DEBUG] self.str_input_dir_base = '{self.str_input_dir_base}'")
        print(f"[DEBUG] Input dir base exists: {os.path.exists(self.str_input_dir_base)}")
        
        # Debug: Check current working directory
        print(f"[DEBUG] Current working directory: {os.getcwd()}")
        
        # Debug: Check if the data directory exists
        data_dir = "../data"
        print(f"[DEBUG] Data directory '{data_dir}' exists: {os.path.exists(data_dir)}")
        
        # Debug: If data dir exists, show its contents
        if os.path.exists(data_dir):
            print(f"[DEBUG] Contents of '{data_dir}':")
            for item in os.listdir(data_dir):
                item_path = os.path.join(data_dir, item)
                print(f"  - '{item}' ({'dir' if os.path.isdir(item_path) else 'file'})")
        
        # Debug: Try absolute path
        abs_data_dir = os.path.abspath(data_dir)
        print(f"[DEBUG] Absolute data directory: {abs_data_dir}")
        print(f"[DEBUG] Absolute data directory exists: {os.path.exists(abs_data_dir)}")
        
        # Debug: Try different variations of the dataset name
        possible_names = [
            dataset_name,
            dataset_name.upper(),
            dataset_name.lower(),
            "MMLLM_Phishing",
            "mmllm_phishing",
            "Mmllm_Phishing"
        ]
        
        for name in possible_names:
            test_path = os.path.join(self.str_input_dir_base, name)
            print(f"[DEBUG] Testing path '{test_path}': exists = {os.path.exists(test_path)}")
        
        # Let's also try to find any folders that might match
        if os.path.exists(self.str_input_dir_base):
            print(f"[DEBUG] All items in input_dir_base:")
            for item in os.listdir(self.str_input_dir_base):
                item_path = os.path.join(self.str_input_dir_base, item)
                if os.path.isdir(item_path):
                    print(f"  - Directory: '{item}'")
                    # Check if this directory has the expected structure
                    has_subfolders = any(os.path.isdir(os.path.join(item_path, sub)) 
                                       for sub in os.listdir(item_path) if os.path.isdir(os.path.join(item_path, sub)))
                    if has_subfolders:
                        print(f"    ----> Has subdirectories (might be our dataset)")
        
        # For now, let's manually construct a working path if we can find the right directory
        base_path = f'{self.str_input_dir_base}/{dataset_name}'
        
        # If the constructed path doesn't exist, let's try to find the right one
        if not os.path.exists(base_path) and os.path.exists(self.str_input_dir_base):
            print("[DEBUG] Trying to find the correct dataset directory...")
            for item in os.listdir(self.str_input_dir_base):
                item_path = os.path.join(self.str_input_dir_base, item)
                if os.path.isdir(item_path) and 'phishing' in item.lower():
                    print(f"[DEBUG] Found potential dataset directory: '{item}'")
                    base_path = item_path
                    break
        
        print(f"[DEBUG] Final base_path: {base_path}")
        print(f"[DEBUG] Final base_path exists: {os.path.exists(base_path)}")
        
        # Continue with the rest only if we have a valid path
        if not os.path.exists(base_path):
            print("[ERROR] Cannot find the dataset directory. Please check the path.")
            return
        
        # Use os.walk to find all folders with the required files
        print("[DEBUG] Using os.walk to find folders with required files:")
        valid_folders = []
        
        for root, dirs, files in os.walk(base_path):
            if 'screenshot_aft.png' in files and 'add_info.json' in files:
                valid_folders.append(root)
                print(f"[DEBUG] Found valid folder: {root}")
        
        print(f"[DEBUG] Total valid folders found: {len(valid_folders)}")
        
        # Continue with processing if we found valid folders
        list_data_dir = valid_folders
        
        for data_dir in tqdm(list_data_dir, desc=f"{dataset_name}"):
            data_dir = os.path.normpath(data_dir)
            path_parts = data_dir.split(os.sep)
            str_hash = path_parts[-1]
            str_brand = path_parts[-2]
    
            ss_path = os.path.join(data_dir, 'screenshot_aft.png')
            html_path = os.path.join(data_dir, 'add_info.json')
    
            with open(html_path, 'r', encoding='utf-8') as f:
                html_info = json.load(f).get('html_brand_info', '')
    
            encoded_image = crop_encode_image_base64(ss_path)
    
            for input_mode in InputMode:
                # ✅ Skip if already processed
                output_dir = os.path.join(self.str_output_dir_base, dataset_name, 'Phase1_GPT', input_mode.value, str_brand)
                os.makedirs(output_dir, exist_ok=True)
                output_file = os.path.join(output_dir, f"{str_hash}.json")
                if os.path.exists(output_file):
                    print(f"[SKIP] {str_brand}/{str_hash} ({input_mode.value}) already processed")
                    continue
    
                self.load_prompt_text(input_mode)
                prompt = self.create_identification_prompt(input_mode, encoded_image, html_info)
    
                try:
                    response = self.query(prompt)
                    res_content = response.choices[0].message.content
                except Exception as e:
                    res_content = str(e)
                    result = format_model_response(str_hash, res_content, is_error=True, is_safety_triggered=False)
                else:
                    result = format_model_response(str_hash, res_content, is_error=False, is_safety_triggered=False)
                    if hasattr(response, "usage"):
                        result.update({
                            'completion_tokens': response.usage.completion_tokens,
                            'prompt_tokens': response.usage.prompt_tokens,
                            'total_tokens': response.usage.total_tokens
                        })
    
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=4)

    def _get_legit_domain_from_gpt(self, brand: str) -> str:
            """Tranco-first lookup → GPT fallback. Returns empty string if neither found."""
            brand_key = brand.strip().lower()
            _debug(f"_get_legit_domain_from_gpt: brand='{brand}' (normalized='{brand_key}')")
    
            # 1) Tranco-first
            try:
                # exact or substring match in tranco_set
                matches = [d for d in self.tranco_set if brand_key in d]
                if matches:
                    chosen = matches[0]
                    _debug(f"Tranco hit for '{brand}': {chosen}")
                    return chosen
                _debug(f"No Tranco match for '{brand}'")
            except Exception as e:
                _debug(f"Error while checking Tranco list: {e}")
    
            # 2) Ask GPT if Tranco didn't return anything
            try:
                prompt = (
                    f"What is the official website domain of the brand '{brand}'? "
                    f"Reply with only the domain name (e.g. example.com). "#If you are not sure, reply with 'UNKNOWN'.
                )
                _debug(f"Querying GPT for legit domain (brand='{brand}')")
                resp = self.client.chat.completions.create(
                    model=self.str_model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=20,
                    temperature=0
                )
                raw = getattr(resp.choices[0].message, "content", "") or resp.choices[0].message.content
                domain_raw = raw.strip().lower()
                _debug(f"GPT raw response for domain: '{domain_raw}'")
                domain = _extract_domain_from_url(domain_raw)
                if not domain or domain in ("unknown", ""):
                    _debug(f"GPT returned no usable domain for '{brand}'")
                    return ""
                _debug(f"GPT-suggested domain for '{brand}': {domain}")
                return domain
            except Exception as e:
                _debug(f"GPT domain lookup failed for '{brand}': {e}")
                return ""

    def _generate_supporting_evidence(self, brand, suspect, legit, matched, info):
        """Ask GPT for ~70 words of supporting explanation. Debugs prompt/response."""
        prompt = (
            f"Write a clear ~100-word supporting explanation for why the comparison between "
            f"the suspect domain '{suspect}' and the legitimate domain '{legit}' for brand '{brand}' "
            f"resulted in verification={matched}. Include the key registrar and DNS signals: {info}."
            f"\nDo not include any extra metadata—only the explanation."
        )
        _debug(f"Generating supporting evidence with GPT. Prompt (truncated): {prompt[:200]}...")
        try:
            resp = self.client.chat.completions.create(
                model=self.str_model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=130,
                temperature=0.7
            )
            raw = getattr(resp.choices[0].message, "content", "") or resp.choices[0].message.content
            evidence = raw.strip()
            _debug(f"Evidence received (len={len(evidence.split())} words, chars={len(evidence)}).")
            # If evidence is too short, log and return as-is
            return evidence
        except Exception as e:
            _debug(f"Evidence generation failed: {e}")
            return "Supporting evidence could not be generated due to an API error."
    def _call_gpt_api(self, prompt: str) -> str:
        """Generic GPT call for short text prompts (returns raw content)."""
        resp = self.client.chat.completions.create(
            model=self.str_model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=10,
            temperature=0
        )
        return getattr(resp.choices[0].message, "content", "").strip()
            

    def phase2_dns_verification(self, input_dataset: InputDataset):
        """Phase 2 with step-by-step debug logging."""
        dataset_name = input_dataset.value
        _debug(f"Starting Phase 2 DNS verification for dataset: '{dataset_name}'")
        phase1_dir = os.path.join(self.str_output_dir_base, dataset_name, "Phase1_GPT")
        _debug(f"Expected Phase1 base dir: {phase1_dir}")

        summary_path = os.path.join(self.str_output_dir_base, dataset_name, "Phase2_GPT", "Phase2_Res_Summary.csv")
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        if not os.path.exists(summary_path):
            with open(summary_path, "w", encoding="utf-8-sig") as f:
                f.write("Dataset,Mode,Brand,Hash,SuspectDomain,LegitDomain,isLegitimate,Info,InTranco\n")#isLegitimate==Verified ani i assumed
            _debug(f"Created summary CSV at {summary_path}")

        for mode in [ "both"]:#"ss","html", 
            base_dir = os.path.join(phase1_dir, mode)
            _debug(f"Checking mode '{mode}' base_dir: {base_dir} (exists={os.path.exists(base_dir)})")
            if not os.path.exists(base_dir):
                _debug(f"Skipping mode '{mode}' because directory not found.")
                continue

            try:
                brands = os.listdir(base_dir)
            except Exception as e:
                _debug(f"Failed to list brands in {base_dir}: {e}")
                continue

            _debug(f"Found {len(brands)} brands in mode '{mode}': {brands[:10]}{'...' if len(brands)>10 else ''}")

            for brand in brands:
                brand_dir = os.path.join(base_dir, brand)
                if not os.path.isdir(brand_dir):
                    _debug(f"Skipping non-directory entry: {brand_dir}")
                    continue

                _debug(f"Processing brand '{brand}' (dir: {brand_dir})")
                try:
                    files = os.listdir(brand_dir)
                except Exception as e:
                    _debug(f"Failed to list files in {brand_dir}: {e}")
                    continue

                for file in files:
                    if not file.endswith(".json"):
                        _debug(f"Skipping non-json file {file}")
                        continue

                    hash_val = file.replace(".json", "")
                    p1_json_path = os.path.join(brand_dir, file)
                    _debug(f"Phase1 JSON found: {p1_json_path}")

                   

                    phishing_base = r"C:/Users/DELL/Desktop/Phishing/data/MMLLM_Phishing"
                    search_pattern = os.path.join(phishing_base, "**", brand, hash_val, "add_info.json")
                    matches = glob.glob(search_pattern, recursive=True)
    
                    if not matches:
                        print(f"[ERROR] Cannot find add_info.json for Brand={brand}, Hash={hash_val}")
                        continue
    
                    add_info_path = matches[0]
                    print(f"[DEBUG] Found add_info.json: {add_info_path}")
    
                       

                    try:
                        with open(add_info_path, encoding="utf-8") as f:
                            add_info = json.load(f)
                    except Exception as e:
                        _debug(f"Failed to read add_info.json for {brand}/{hash_val}: {e}")
                        continue

                    suspect_url = add_info.get("Url") or add_info.get("url")
                    _debug(f"Extracted suspect_url for {brand}/{hash_val}: '{suspect_url}'")
                    if not suspect_url:
                        _debug(f"No suspect URL in add_info.json for {brand}/{hash_val}; skipping")
                        continue

                    suspect_domain = _extract_domain_from_url(suspect_url)
                    _debug(f"Normalized suspect_domain: '{suspect_domain}'")
                    if not suspect_domain:
                        _debug(f"Could not extract domain from suspect_url '{suspect_url}'; skipping")
                        continue

                    # get legit domain (Tranco-first, then GPT)
                    legit_domain = self._get_legit_domain_from_gpt(brand)
                    _debug(f"Legit domain resolved for brand '{brand}': '{legit_domain}'")
                    if not legit_domain:
                        _debug(f"No legit domain available for brand '{brand}' (hash {hash_val}). Skipping verification for this item.")
                        continue

                    # run DNS/WHOIS check
                    try:
                        _debug(f"Running DNS/WHOIS comparison: suspect='{suspect_domain}' vs legit='{legit_domain}'")
                        matched, info = _dns_check_pair(suspect_domain, legit_domain)
                        _debug(f"DNS check result for {brand}/{hash_val}: matched={matched}, info='{info}'")
                    except Exception as e:
                        _debug(f"DNS check failed for {brand}/{hash_val}: {e}")
                        matched, info = False, f"DNS check exception: {e}"

                    # generate supporting evidence via GPT
                    try:
                        _debug("Generating supporting evidence via GPT (this will call API).")
                        evidence = self._generate_supporting_evidence(brand, suspect_domain, legit_domain, matched, info)
                        _debug(f"Supporting evidence generated (len chars={len(evidence)}).")
                    except Exception as e:
                        _debug(f"Supporting evidence generation error for {brand}/{hash_val}: {e}")
                        evidence = "Supporting evidence generation failed."

                    # get confidence score via GPT (inline, no extra function)
                    try:
                        _debug("Requesting GPT confidence score (0–100).")
                        prompt = (
                            f"Here is your answer:\n\n{evidence}\n\n"
                            f"Question: How confident are you in this answer on a scale of 0.00 to 10.00 "
                            f"(in 2 decimal places), 10.00 being absolutely confident, 0.00 being not confident?\n"
                            f"Reply with only a number (0.00–10.00)."
                        )
                        response = self._call_gpt_api(prompt)  # your existing GPT call
                        confidence_score = float(response.strip().split()[0])
                        confidence_score = max(0.0, min(10.0, confidence_score))  # clamp to [0,100]
                        _debug(f"Confidence score returned: {confidence_score}")
                    except Exception as e:
                        _debug(f"Confidence score error for {brand}/{hash_val}: {e}")
                        confidence_score = -1.0

                    # build result and save
                    result = {
                        "Brand": brand,
                        "Hash": hash_val,
                        "SuspectDomain": suspect_domain,
                        "LegitDomain": legit_domain,
                        "IsLegitimate": matched, #Verified
                        "Info": info,
                        "ConfidenceScore":confidence_score,
                        "SupportingEvidence": evidence
                    }

                    out_dir = os.path.join(self.str_output_dir_base, dataset_name, "Phase2_GPT", mode, brand)
                    os.makedirs(out_dir, exist_ok=True)
                    out_file = os.path.join(out_dir, f"{hash_val}.json")
                    try:
                        with open(out_file, "w", encoding="utf-8") as f:
                            json.dump(result, f, indent=4)
                        _debug(f"Wrote Phase2 JSON to {out_file}")
                    except Exception as e:
                        _debug(f"Failed to write Phase2 JSON for {brand}/{hash_val}: {e}")

                    # append to CSV summary
                    try:
                        in_tranco = "Yes" if suspect_domain in self.tranco_set else "No"
                        safe_info = str(info).replace(",", ";")
                        with open(summary_path, "a", encoding="utf-8-sig") as f:
                            f.write(f"{dataset_name},{mode},{brand},{hash_val},{suspect_domain},{legit_domain},{matched},{safe_info},{in_tranco}\n")
                        _debug(f"Appended summary CSV for {brand}/{hash_val}")
                    except Exception as e:
                        _debug(f"Failed to append summary CSV for {brand}/{hash_val}: {e}")

        _debug("Phase 2 DNS verification complete.")

    def analyze_live_capture(self, html_content: str, screenshot_base64: str, url: str):
        """
        Phase 1 + Phase 3 verification for live Chrome Extension captures.
        Now includes SSL/TLS certificate analysis.
        """
        _debug("[PHASE4] Starting Live Capture Analysis")
    
        input_mode = InputMode.BOTH
        self.load_prompt_text(input_mode)
        prompt = self.create_identification_prompt(input_mode, screenshot_base64, html_content)
    
        # --- Phase 1: Brand identification ---
        try:
            response = self.query(prompt)
            phase1_output = format_model_response("live", response.choices[0].message.content, False, False)
            brand = phase1_output.get("Brand", "").strip()
            _debug(f"[PHASE4] Brand identified: {brand}")
        except Exception as e:
            return {"status": "fail", "error": str(e)}
    
        # --- Phase 3: Domain verification ---
        suspect_domain = _extract_domain_from_url(url)
        legit_domain = self._get_legit_domain_from_gpt(brand)
        matched, info = _dns_check_pair(suspect_domain, legit_domain)
        _debug(f"[PHASE4] DNS check done → matched={matched}, info={info}")
    
        # --- SSL/TLS Certificate Analysis ---
        ssl_details = self._get_ssl_details(suspect_domain)
        if ssl_details["SSL_Valid"]:
            ssl_comment = (
                f"SSL valid; issued by {ssl_details['SSL_Issuer']}; "
                f"certificate age ≈ {ssl_details['SSL_AgeDays']} days."
            )
        else:
            ssl_comment = f"SSL invalid or error: {ssl_details.get('Error', 'Unknown')}"
    
        _debug(f"[PHASE4] SSL info summary: {ssl_comment}")
    
        # --- Generate supporting explanation via GPT ---
        combined_info = f"{info}; {ssl_comment}"
        evidence = self._generate_evidence(brand, suspect_domain, legit_domain, matched, combined_info, ssl_details)
        # --- Generate supporting explanation via GPT ---
        combined_info = f"{info}; {ssl_comment}"
        evidence = self._generate_evidence(brand, suspect_domain, legit_domain, matched, combined_info, ssl_details)
        
        # Ensure SSL info always appears in explanation
        if ssl_details:
            if ssl_details.get("SSL_Valid"):
                extra_ssl_text = (
                    f"\n\n🔒 SSL Certificate Details:\n"
                    f"Issuer: {ssl_details.get('SSL_Issuer', 'Unknown')}\n"
                    f"Common Name: {ssl_details.get('SSL_CommonName', 'N/A')}\n"
                    f"Valid From: {ssl_details.get('SSL_NotBefore', 'N/A')}\n"
                    f"Valid Until: {ssl_details.get('SSL_NotAfter', 'N/A')}\n"
                    f"Certificate Age: {ssl_details.get('SSL_AgeDays', 'N/A')} days\n"
                )
            else:
                extra_ssl_text = f"\n\n⚠️ SSL Certificate Error: {ssl_details.get('Error', 'Unknown')}"
            evidence += extra_ssl_text

    
        # --- Confidence estimation ---
        confidence_prompt = (
            f"Here is your answer:\n\n{evidence}\n\n"
            f"Question: How confident are you in this answer on a scale of 0.00 to 10.00?\n"
            f"Reply with only a number."
        )
        try:
            conf_raw = self._call_gpt_api(confidence_prompt)
            confidence = float(conf_raw.strip().split()[0])
        except Exception:
            confidence = -1.0
    
        # --- Final Output ---
        return {
            "status": "success",
            "brand": brand,
            "url": url,
            "suspect_domain": suspect_domain,
            "legit_domain": legit_domain,
            "is_phishing": not matched,
            "confidence": confidence,
            "explanation": evidence,
            "info": info,
            "ssl_details": ssl_details,
        }
    def phase1_and_phase2_live(self, ss_path, html_content, url):
        """
        Phase 1 + Phase 3 (SSL/TLS + GPT evidence) pipeline for browser extension live capture.
        """
        # ---------- Phase 1: Brand Identification ----------
        encoded_image = crop_encode_image_base64(ss_path)
        self.load_prompt_text(InputMode.BOTH)
        prompt = self.create_identification_prompt(InputMode.BOTH, encoded_image, html_content)
        
        try:
            response = self.query(prompt)
            res_content = response.choices[0].message.content
            phase1_result = format_model_response("live", res_content, is_error=False, is_safety_triggered=False)
            brand = phase1_result.get("Brand", "Unknown")
        except Exception as e:
            return {"status": "fail", "error": str(e)}
    
        # ---------- Phase 3: SSL/TLS Verification ----------
        import ssl
        import socket
        from datetime import datetime
    
        def fetch_ssl_info(domain):
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
                subject = dict(x[0] for x in cert.get("subject", ())).get("commonName", "")
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_valid = (not_after - not_before).days
                valid_now = not_before <= datetime.utcnow() <= not_after
                return {
                    "SSL_Valid": valid_now,
                    "SSL_Issuer": issuer,
                    "SSL_CommonName": subject,
                    "SSL_NotBefore": not_before.isoformat(),
                    "SSL_NotAfter": not_after.isoformat(),
                    "SSL_AgeDays": days_valid,
                }
            except Exception as e:
                return {"SSL_Valid": False, "SSL_Error": str(e)}
    
        # ---------- Domain + SSL Info ----------
        suspect_domain = _extract_domain_from_url(url)
        legit_domain = self._get_legit_domain_from_gpt(brand)
        ssl_info = fetch_ssl_info(suspect_domain)
    
        # Combine info summary
        if ssl_info.get("SSL_Valid"):
            ssl_text = (
                f"The SSL certificate is valid, issued by '{ssl_info.get('SSL_Issuer')}', "
                f"and is active for about {ssl_info.get('SSL_AgeDays')} days."
            )
        else:
            ssl_text = f"The SSL certificate is invalid or missing ({ssl_info.get('SSL_Error', 'N/A')})."
    
        # DNS check
        matched, info = _dns_check_pair(suspect_domain, legit_domain)
    
        # ---------- Generate GPT-based Supporting Evidence ----------
        evidence = self._generate_supporting_evidence(
            brand=brand,
            suspect=suspect_domain,
            legit=legit_domain,
            matched=matched,
            info=f"{info}; {ssl_text}"
        )
    
        # ---------- Final Output ----------
        return {
            "is_phishing": not matched,
            "confidence_score": 9.2,
            "explanation": evidence,  # ✅ uses GPT-generated evidence
            "ssl_details": ssl_info,
        }

