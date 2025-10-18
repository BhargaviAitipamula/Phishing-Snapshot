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

class MMLLM_GPT:
    def __init__(self, str_api_key:str):
        self.str_api_key = str_api_key
        self.dict_phase1_system_msg = {}
        self.dict_phase1_res_format = {}
        self.dict_phase2_system_msg = {}
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

        str_phase2_prompt_path = dict_system_prompt_path.get(Phase2Mode.Phase2)
        assert str_phase2_prompt_path, f"Unknown Input mode {Phase2Mode.Phase2}"

        with open(str_phase2_prompt_path, encoding='utf-8') as f:
            str_phase2_system_prompt = f.read()
            self.dict_phase2_system_msg = {
                "role": "system",
                "content": [{"type": "text", "text": str_phase2_system_prompt}],
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

    # def create_brandcheck_prompt(self, groundtruth, prediction):
    #     return [
    #         self.dict_phase2_system_msg,
    #         {"role": "user", "content": [{"type": "text", "text": f"Ground Truth: \"{groundtruth}\"\n\"Prediction:\"{prediction}\""}]}
    #     ]
    def create_brandcheck_prompt(self, groundtruth, prediction):
        # self.dict_phase2_system_msg is guaranteed by the call in phase2_phishing_classification
        return [
            self.dict_phase2_system_msg,
            {"role": "user", "content": f'Ground Truth: "{groundtruth}"\nPrediction: "{prediction}"'}
        ]

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
        
            # Use live_capture folder
        if input_dataset == InputDataset.LiveCapture:
            base_path = os.path.join(self.str_input_dir_base, dataset_name)
        else:
            base_path = os.path.join(self.str_input_dir_base, dataset_name)

        if not os.path.exists(base_path):
            print(f"[ERROR] Cannot find dataset directory: {base_path}")
            return

        # Walk folders like normal datasets
        list_data_dir = load_unzipped_data(base_path)  # ✅ This gets html + ss


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

                    
  
    # def phase2_phishing_classification(self, input_dataset: InputDataset):
    #     dataset_name = input_dataset.value
    #     summary_path = os.path.join(self.str_output_dir_base, dataset_name, 'Phase2_GPT', "Phase2_Res_Summary.csv")
    #     os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    
    #     print(f"[DEBUG] dataset_name = '{dataset_name}'")
    #     print(f"[DEBUG] self.str_output_dir_base = '{self.str_output_dir_base}'")
    #     print(f"[DEBUG] Current working directory: {os.getcwd()}")
    
    #     # ✅ Load Phase 2 system prompt once so self.dict_phase2_system_msg is valid
    #     self.load_prompt_text(InputMode.SS)
    
    #     # Check Phase1 output directory
    #     phase1_dir = os.path.join(self.str_output_dir_base, dataset_name, 'Phase1_GPT')
    #     print(f"[DEBUG] Phase1 output dir: {phase1_dir}")
    #     print(f"[DEBUG] Phase1 output dir exists: {os.path.exists(phase1_dir)}")
    #     if os.path.exists(phase1_dir):
    #         print("[DEBUG] Contents of Phase1 output dir:")
    #         for item in os.listdir(phase1_dir):
    #             print(f"  - {item}")
    #     else:
    #         print("[ERROR] Phase1 output directory not found; Phase2 cannot proceed.")
    #         return
    
    #     # Create summary file if missing
    #     if not os.path.exists(summary_path):
    #         with open(summary_path, 'w', encoding='utf-8') as f:
    #             f.write('Dataset,InputMode,Brand,Hash,Phase1Pred,Phase2Matched\n')
    
    #     for input_mode in InputMode:
    #         print(f"\n[DEBUG] === Processing InputMode: {input_mode.value} ===")
    #         base_dir = os.path.join(self.str_output_dir_base, dataset_name, 'Phase1_GPT', input_mode.value)
    #         print(f"[DEBUG] Base dir for Phase1 files: {base_dir}")
    #         print(f"[DEBUG] Base dir exists: {os.path.exists(base_dir)}")
    
    #         # Find all Phase1 output JSONs
    #         input_files = glob.glob(f"{base_dir}/**/*.json", recursive=True)
    #         input_files = [f.replace('\\', '/') for f in input_files]
    #         print(f"[DEBUG] Found {len(input_files)} JSON files for {input_mode.value}")
    #         for test_file in input_files[:5]:
    #             print(f"  - {test_file}")
    
    #         for input_path in input_files:
    #             props = input_path.split('/')
    #             hash_val = props[-1].replace('.json', '')
    #             brand = props[-2]
    
    #             # Read Phase1 result JSON
    #             try:
    #                 with open(input_path, encoding='utf-8') as f:
    #                     data = json.load(f)
    #             except json.JSONDecodeError as e:
    #                 print(f"[ERROR] Failed to parse JSON: {input_path} -> {e}")
    #                 continue
    
    #             if data.get('Error'):
    #                 print(f"[SKIP] {input_path} contains Error flag.")
    #                 continue
    #             if 'Brand' not in data:
    #                 print(f"[ERROR] Missing 'Brand' key in {input_path}")
    #                 continue
    
    #             pred = data['Brand']
    #             print(f"[DEBUG] Processing {brand}/{hash_val} | Phase1 prediction: {pred}")
    
    #             try:
    #                 prompt = self.create_brandcheck_prompt(brand, pred)
    #                 response = self.query(prompt)
    #                 res_content = response.choices[0].message.content
    #                 result = format_phase2_response(res_content, is_error=False, is_safety_triggered=False)
    
    #                 if hasattr(response, "usage"):
    #                     result.update({
    #                         'completion_tokens': response.usage.completion_tokens,
    #                         'prompt_tokens': response.usage.prompt_tokens,
    #                         'total_tokens': response.usage.total_tokens
    #                     })
    #             except Exception as e:
    #                 print(f"[ERROR] Exception during Phase2 inference for {brand}/{hash_val} -> {e}")
    #                 result = format_phase2_response("ERROR", is_error=True, is_safety_triggered=False)
    
    #             # Save individual Phase2 result
    #             out_dir = os.path.join(self.str_output_dir_base, dataset_name, 'Phase2_GPT', input_mode.value, brand)
    #             os.makedirs(out_dir, exist_ok=True)
    #             out_file = os.path.join(out_dir, f"{hash_val}.json")
    #             with open(out_file, 'w', encoding='utf-8') as f:
    #                 json.dump(result, f, indent=4)
    
    #             # Append to summary
    #             with open(summary_path, "a", encoding="utf-8-sig") as f:
    #                 f.write(f'{dataset_name},{input_mode.value},{brand},{hash_val},{pred},{result["BrandMatched"]}\n')
    
    #     print("[DEBUG] Phase 2 processing complete.")
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
            

    def phase3_dns_verification(self, input_dataset: InputDataset):
        """Phase 3 with step-by-step debug logging."""
        dataset_name = input_dataset.value
        _debug(f"Starting Phase 3 DNS verification for dataset: '{dataset_name}'")
        phase1_dir = os.path.join(self.str_output_dir_base, dataset_name, "Phase1_GPT")
        _debug(f"Expected Phase1 base dir: {phase1_dir}")

        summary_path = os.path.join(self.str_output_dir_base, dataset_name, "Phase3_GPT", "Phase3_Res_Summary.csv")
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

                    # find add_info.json (robust)
                    # phishing_base = r"C:/Users/DELL/Desktop/Phishing/data/MMLLM_Phishing"
                    # add_info_path = os.path.join(self.str_input_dir_base, dataset_name,"**", brand, hash_val, "add_info.json")
                    # _debug(f"Looking for add_info at: {add_info_path} (exists={os.path.exists(add_info_path)})")
                    # if not os.path.exists(add_info_path):
                    #     _debug(f"add_info.json not found for {brand}/{hash_val}; skipping")
                    #     continue

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

                    out_dir = os.path.join(self.str_output_dir_base, dataset_name, "Phase3_GPT", mode, brand)
                    os.makedirs(out_dir, exist_ok=True)
                    out_file = os.path.join(out_dir, f"{hash_val}.json")
                    try:
                        with open(out_file, "w", encoding="utf-8") as f:
                            json.dump(result, f, indent=4)
                        _debug(f"Wrote Phase3 JSON to {out_file}")
                    except Exception as e:
                        _debug(f"Failed to write Phase3 JSON for {brand}/{hash_val}: {e}")

                    # append to CSV summary
                    try:
                        in_tranco = "Yes" if suspect_domain in self.tranco_set else "No"
                        safe_info = str(info).replace(",", ";")
                        with open(summary_path, "a", encoding="utf-8-sig") as f:
                            f.write(f"{dataset_name},{mode},{brand},{hash_val},{suspect_domain},{legit_domain},{matched},{safe_info},{in_tranco}\n")
                        _debug(f"Appended summary CSV for {brand}/{hash_val}")
                    except Exception as e:
                        _debug(f"Failed to append summary CSV for {brand}/{hash_val}: {e}")

        _debug("Phase 3 DNS verification complete.")