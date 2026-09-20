import sys
import json
import os
import re
import subprocess
from pathlib import Path
from datetime import datetime

import requests


YARA_EXE = Path(
    r"C:\Program Files (x86)\ossec-agent\active-response\bin"
    r"\yara\yara64.exe"
)

YARA_RULE = Path(
    r"C:\Program Files (x86)\ossec-agent\active-response\bin"
    r"\yara\rules\lab-test.yar"
)

DEBUG_LOG = Path(
    r"C:\WazuhLab\yara-wrapper-debug.log"
)

ACTIVE_RESPONSE_LOG = Path(
    r"C:\Program Files (x86)\ossec-agent\active-response"
    r"\active-responses.log"
)

GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/"
    "v1beta/interactions"
)

GEMINI_MODEL = "gemini-3.8-flash"


def debug(message):
    """Menulis informasi troubleshooting ke debug log."""
    timestamp = datetime.now().isoformat(timespec="seconds")

    with DEBUG_LOG.open("a", encoding="utf-8") as log:
        log.write(f"{timestamp} {message}\n")


def active_response_log(message):
    """Menulis hasil YARA dan AI ke Active Response log Wazuh."""
    safe_message = message.replace("\r", " ").replace("\n", " ")

    with ACTIVE_RESPONSE_LOG.open("a", encoding="utf-8") as log:
        log.write(safe_message + "\n")


def extract_description(yara_output):
    """Mengambil metadata description dari output YARA."""
    match = re.search(
        r'description="([^"]+)"',
        yara_output,
    )

    if match:
        return match.group(1)

    return None


def extract_gemini_text(response_data):
    """Mengambil teks keluaran dari response Gemini."""

    output_text = response_data.get("output_text")

    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    collected_text = []

    for step in response_data.get("steps", []):
        content_items = step.get("content", [])

        if isinstance(content_items, dict):
            content_items = [content_items]

        if not isinstance(content_items, list):
            continue

        for content in content_items:
            if not isinstance(content, dict):
                continue

            text = content.get("text")

            if isinstance(text, str) and text.strip():
                collected_text.append(text.strip())

    if collected_text:
        return " ".join(collected_text)

    return None


def query_gemini(description):
    """
    Mengirim hanya description rule YARA ke Gemini.

    File, isi file, path file, hostname, alamat IP,
    nama agent, dan full alert tidak dikirim.
    """
    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        debug("[GEMINI-ERROR] GEMINI_API_KEY is not available")
        return None

    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
    }

    prompt = (
        "You are assisting a SOC analyst with YARA alert triage. "
        "Explain the security meaning, possible impact, and safe "
        "investigation recommendations for the following YARA rule "
        "description. Do not state that the file is malicious with "
        "certainty. Respond in one concise paragraph. "
        f"YARA rule description: {description}"
    )

    payload = {
        "model": GEMINI_MODEL,
        "input": prompt,
        "store": False,
    }

    debug("[GEMINI] Sending YARA description only")

    try:
        response = requests.post(
            GEMINI_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=(10, 90),
        )
    except requests.ConnectTimeout:
        debug("[GEMINI-ERROR] Connection timed out after 10 seconds")
        return None
    except requests.ReadTimeout:
        debug("[GEMINI-ERROR] Response timed out after 90 seconds")
        return None
    except requests.RequestException as error:
        debug(f"[GEMINI-ERROR] Request failed: {error}")
        return None

    debug(f"[GEMINI] HTTP status: {response.status_code}")

    if response.status_code != 200:
        response_preview = response.text[:500]
        response_preview = response_preview.replace("\r", " ")
        response_preview = response_preview.replace("\n", " ")

        debug(
            "[GEMINI-ERROR] API returned non-success response: "
            f"{response_preview}"
        )
        return None

    try:
        response_data = response.json()
    except ValueError as error:
        debug(f"[GEMINI-ERROR] Invalid JSON response: {error}")
        return None

    ai_response = extract_gemini_text(response_data)

    if not ai_response:
        debug("[GEMINI-ERROR] No generated text found in API response")
        return None

    ai_response = ai_response.replace("\r", " ")
    ai_response = ai_response.replace("\n", " ")
    ai_response = " ".join(ai_response.split())

    debug("[GEMINI] AI enrichment received")

    return ai_response


def main():
    debug("[START] Wrapper started")

    input_line = sys.stdin.readline().strip()

    if not input_line:
        debug("[ERROR] No JSON received from STDIN")
        return 1

    try:
        payload = json.loads(input_line)
        debug("[INPUT] JSON received and parsed")
    except json.JSONDecodeError as error:
        debug(f"[ERROR] Invalid JSON: {error}")
        return 1

    command = payload.get("command")

    if command != "add":
        debug(f"[SKIP] Unsupported command: {command}")
        return 0

    try:
        file_path = Path(
            payload["parameters"]["alert"]["syscheck"]["path"]
        )
        debug(f"[PATH] {file_path}")
    except KeyError as error:
        debug(f"[ERROR] Missing JSON field: {error}")
        return 1
    except TypeError as error:
        debug(f"[ERROR] Invalid syscheck path value: {error}")
        return 1

    if not YARA_EXE.is_file():
        debug(f"[ERROR] YARA executable not found: {YARA_EXE}")
        return 1

    if not YARA_RULE.is_file():
        debug(f"[ERROR] YARA rule not found: {YARA_RULE}")
        return 1

    if not file_path.is_file():
        debug(f"[ERROR] Target file does not exist: {file_path}")
        return 1

    debug("[FILE] Target file exists")

    try:
        result = subprocess.run(
            [
                str(YARA_EXE),
                "-m",
                str(YARA_RULE),
                str(file_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        debug("[ERROR] YARA scan timed out after 30 seconds")
        return 1
    except Exception as error:
        debug(f"[ERROR] Unable to execute YARA: {error}")
        return 1

    debug(f"[YARA] Exit code: {result.returncode}")

    if result.stderr.strip():
        yara_error = result.stderr.strip()
        yara_error = yara_error.replace("\r", " ")
        yara_error = yara_error.replace("\n", " ")
        debug(f"[YARA-STDERR] {yara_error}")

    if not result.stdout.strip():
        debug("[NO-MATCH] No YARA rule matched")
        debug("[END] Wrapper completed")
        return 0

    yara_output = result.stdout.strip()
    yara_output = yara_output.replace("\r", " ")
    yara_output = yara_output.replace("\n", " ")

    debug(f"[MATCH] {yara_output}")

    description = extract_description(yara_output)

    if description:
        debug(f"[DESCRIPTION] {description}")
        ai_response = query_gemini(description)
    else:
        debug("[GEMINI-SKIP] YARA description not found")
        ai_response = None

    if not ai_response:
        ai_response = "None"

    try:
        active_response_log(
            f"wazuh-YARA: INFO - Scan result: {yara_output} | "
            f"chatgpt_response: {ai_response}"
        )

        debug(
            "[AR-LOG] YARA result and AI enrichment written "
            "to active-responses.log"
        )
    except PermissionError as error:
        debug(
            "[AR-LOG-ERROR] Permission denied or log file locked: "
            f"{error}"
        )
        return 1
    except Exception as error:
        debug(f"[AR-LOG-ERROR] {error}")
        return 1

    debug("[END] Wrapper completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
