import re
from enum import Enum
import PIL.Image
import base64
from io import BytesIO
import os

# ========== Enums ==========
class Phase2Mode(Enum):
    Phase2 = 'phase2'

class InputMode(Enum):
    SS = 'ss'
    HTML = 'html'
    BOTH = 'both'  
    LIVE = 'live'  

class InputDataset(Enum):
    MMLLM_Benign = 'MMLLM_Benign' 
    MMLLM_Phishing = 'MMLLM_Phishing'
    APW_Wild = 'APW-Wild'
    Pert_BG = 'Pert-BG'
    Pert_Foot = 'Pert-BG'
    Pert_Text = 'Pert-Text'
    Pert_Typo = 'Pert-Typo'
    LiveCapture = 'live_capture' 

# ========== Global Paths ==========
str_input_dir_base = '../input/'
str_output_dir_base = '../output/'

dict_system_prompt_path = {
    InputMode.SS: '../prompts/system_prompt_ss.txt',
    InputMode.HTML: '../prompts/system_prompt_html.txt',
    InputMode.BOTH: '../prompts/system_prompt_both.txt',
    Phase2Mode.Phase2: '../prompts/system_prompt_phase2.txt'        
}

dict_response_prompt_path = {
    InputMode.SS: '../prompts/response_format_prompt.txt',
    InputMode.HTML: '../prompts/response_format_prompt_html.txt',
    InputMode.BOTH: '../prompts/response_format_prompt.txt'
}

# ========== Image Preprocessing ==========

def crop_encode_image_PIL(str_image_path: str):
    """Crop image to meet Gemini size limits and return PIL.Image"""
    int_gemini_max_img = 5 * 1024 * 1024
    int_img_file_size = os.path.getsize(str_image_path)
    image = PIL.Image.open(str_image_path)

    if int_img_file_size > int_gemini_max_img:
        f_reduce_ratio = int_gemini_max_img / int_img_file_size
        int_reduce_height = int(image.height * f_reduce_ratio)
        image = image.crop((0, 0, image.width, int_reduce_height))

    return image

def crop_encode_image_base64(str_image_path: str):
    """Crop (if needed) and return base64-encoded image string"""
    int_max_height = 1568
    im = PIL.Image.open(str_image_path)

    if im.height > int_max_height:
        im = im.crop((0, 0, im.width, int_max_height))

    buffered = BytesIO()
    fmt = "PNG" if ".png" in str_image_path.lower() else "JPEG"
    im.save(buffered, format=fmt)
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

# ========== Regex Parsers ==========

def search_for_response(pattern, response_text):
    
    try: 
        return re.search(pattern, response_text).group(1).strip()
    except:
        return ""

# ========== Phase 1 Response Formatter ==========

def format_model_response(folder_hash, response_text: str, is_error: bool = False, is_safety_triggered: bool = False):
    print(f"\n[📥 DEBUG] GPT Response for {folder_hash}:\n{response_text}\n{'-'*60}")
    if is_error:
        error_msg = "Error Occurred"
        b_error = True
    elif is_safety_triggered:
        error_msg = "Safety Reasons"
        b_error = True
    elif "payload size exceeds the limit" in response_text:
        error_msg = "Payload exceeds limit"
        b_error = True
    elif len(response_text.strip()) == 0:
        error_msg = "Indeterminate"
        b_error = True
    else: 
        b_error = False
        return {
            "Folder Hash": folder_hash,
            "Brand": search_for_response(r'Brand: (.+)', response_text),
            "Has_Credentials": search_for_response(r'Has_Credentials: (.+)', response_text),
            "Has_Call_To_Actions": search_for_response(r'Has_Call_To_Action: (.+)', response_text),
            "List of Credentials fields": search_for_response(r'List_of_credentials: (.+)', response_text),
            "List of Call-To-Actions": search_for_response(r'List_of_call_to_action: (.+)', response_text),
            "Confidence Score": search_for_response(r'Confidence_Score: (.+)', response_text),
            "Supporting Evidence": search_for_response(r'Supporting_Evidence: (.+)', response_text),
            "Error": b_error
        }

    return {
        "Folder Hash": folder_hash,
        "Brand": error_msg,
        "Has_Credentials": error_msg,
        "Has_Call_To_Actions": error_msg,
        "List of Credentials fields": error_msg,
        "List of Call-To-Actions": error_msg,
        "Confidence Score": error_msg,
        "Supporting Evidence": error_msg,
        "Error": b_error
    }

# ========== Phase 2 Response Formatter ==========

def format_phase2_response(response_text: str, is_error: bool, is_safety_triggered: bool):
    if is_error:
        return {"BrandMatched": False, "Explanation": "Error Occurred", "Error": True}
    elif is_safety_triggered:
        return {"BrandMatched": False, "Explanation": "Safety Reasons", "Error": True}
    elif "payload size exceeds the limit" in response_text:
        return {"BrandMatched": False, "Explanation": "Payload exceeds limit", "Error": True}
    elif len(response_text.strip()) == 0:
        return {"BrandMatched": False, "Explanation": "Indeterminate", "Error": True}
    else:
        return {
            "BrandMatched": search_for_response(r'BrandMatch: (.+)', response_text),
            "Explanation": search_for_response(r'Explanation: (.+)', response_text),
            "Error": False
        }

# ========== Unzipped Data Loader ==========

def load_unzipped_data(data_dir):
    """
    Walks through unzipped data directory to get HTML and PNG paths.
    Returns a list of dictionaries with keys: html_path, img_path, folder
    """
    data = []
    for root, dirs, files in os.walk(data_dir):
        html_path = None
        img_path = None
        for file in files:
            if file.endswith(".html"):
                html_path = os.path.join(root, file)
            elif file.endswith(".png"):
                img_path = os.path.join(root, file)
        if html_path and img_path:
            data.append({
                "folder": root,
                "html_path": html_path,
                "img_path": img_path
            })
    return data

def process_live_capture(html_content: str = None, screenshot_b64: str = None):
    """
    Converts live capture input into the format expected by MMLLM_GPT.
    html_content: raw HTML string from live page (optional)
    screenshot_b64: base64-encoded screenshot (optional)
    
    Returns:
        dict: {"html": ..., "screenshot": PIL.Image or base64 string}
    """
    output = {}
    
    # Handle screenshot
    if screenshot_b64:
        try:
            screenshot_bytes = base64.b64decode(screenshot_b64)
            image = PIL.Image.open(BytesIO(screenshot_bytes))
            # Crop to max height if needed
            max_height = 1568
            if image.height > max_height:
                image = image.crop((0, 0, image.width, max_height))
            output['screenshot'] = image
        except Exception as e:
            print(f"[⚠️ WARNING] Failed to decode screenshot: {e}")
            output['screenshot'] = None
    else:
        output['screenshot'] = None

    # Handle HTML
    if html_content:
        output['html'] = html_content
    else:
        output['html'] = None

    return output
