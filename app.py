"""
app.py
------
ThreadLens - Lightweight Threat Intelligence Checker.

This file owns all UI, validation, orchestration, and verdict logic.
It never talks to an external API directly except Gemini - all threat
intelligence collection lives in sources.py and is called dynamically
through the SOURCES registry, so new sources can be added there without
touching this file.

Run with:
    streamlit run app.py

Setup:
    1. Create a file named ".env" in this folder with:
           VIRUSTOTAL_API_KEY=your_key_here
           GEMINI_API_KEY=your_key_here
    2. Install dependencies:
           pip install -r requirements.txt
    3. Run the app:
           streamlit run app.py
"""

import ipaddress
import os
import re
from urllib.parse import urlparse

import streamlit as st
from dotenv import load_dotenv

from sources import SOURCES

# Load VIRUSTOTAL_API_KEY / GEMINI_API_KEY from a local .env file, if present.
load_dotenv()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_ip(value: str) -> tuple[bool, str]:
    """Validate an IPv4 or IPv6 address using the ipaddress module."""
    value = value.strip()
    if not value:
        return False, "Please enter an IP address."
    try:
        ipaddress.ip_address(value)
        return True, ""
    except ValueError:
        return False, f"'{value}' is not a valid IPv4 or IPv6 address."


def validate_domain(value: str) -> tuple[bool, str]:
    """Validate a plain domain name (no protocol, valid characters)."""
    value = value.strip()
    if not value:
        return False, "Please enter a domain."
    if "://" in value or value.startswith("//"):
        return False, "Please enter a domain without a protocol (e.g. example.com, not https://example.com)."
    if "/" in value or " " in value:
        return False, "Domain must not contain slashes or spaces."

    # Simple, readable domain-format check: labels separated by dots,
    # letters/digits/hyphens only, ending in a 2+ letter TLD.
    domain_pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
    )
    if not domain_pattern.match(value):
        return False, f"'{value}' does not look like a valid domain."
    return True, ""


def validate_url(value: str) -> tuple[bool, str]:
    """Validate that a string is a well-formed http(s) URL."""
    value = value.strip()
    if not value:
        return False, "Please enter a URL."
    if not value.startswith(("http://", "https://")):
        return False, "URL must start with http:// or https://."

    parsed = urlparse(value)
    if not parsed.hostname:
        return False, "URL does not contain a valid hostname."
    return True, ""


VALIDATORS = {
    "IP Address": validate_ip,
    "Domain": validate_domain,
    "URL": validate_url,
}

PLACEHOLDERS = {
    "IP Address": "8.8.8.8",
    "Domain": "example.com",
    "URL": "https://example.com",
}


# ---------------------------------------------------------------------------
# Verdict logic (deterministic - Gemini does NOT decide this)
# ---------------------------------------------------------------------------

def calculate_verdict(results: list[dict]) -> tuple[str, str]:
    """
    Derive a verdict + confidence directly from source data.
    Gemini is used only for explanation, never for the final call.

    Returns (verdict, confidence) where verdict is one of:
        SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN
    """
    vt_result = next((r for r in results if r["source"] == "VirusTotal"), None)

    any_success = any(r["success"] for r in results)
    if not any_success:
        return "UNKNOWN", "Low"

    if vt_result and vt_result["success"]:
        data = vt_result["data"]
        malicious = data.get("malicious", 0) or 0
        suspicious = data.get("suspicious", 0) or 0
        harmless = data.get("harmless", 0) or 0

        if malicious >= 3:
            return "MALICIOUS", "High"
        if malicious >= 1:
            return "MALICIOUS", "Medium"
        if suspicious >= 2:
            return "SUSPICIOUS", "Medium"
        if suspicious == 1:
            return "SUSPICIOUS", "Low"
        if harmless > 0:
            return "SAFE", "Medium"

    # VirusTotal gave no usable signal (missing key, error, or a freshly
    # submitted URL with no stats yet) - not enough evidence either way.
    return "UNKNOWN", "Low"


VERDICT_STYLE = {
    "SAFE": ("🟢", "#1e7e34", "#e6f4ea"),
    "SUSPICIOUS": ("🟡", "#8a6d00", "#fff8e1"),
    "MALICIOUS": ("🔴", "#a71d2a", "#fdecea"),
    "UNKNOWN": ("⚪", "#4a4a4a", "#f1f1f1"),
}

VERDICT_MEANING = {
    "SAFE": "Available intelligence shows no significant malicious indicators, but this does not guarantee safety.",
    "SUSPICIOUS": "Some indicators require caution or further investigation.",
    "MALICIOUS": "Multiple threat intelligence signals indicate potential malicious activity.",
    "UNKNOWN": "There is insufficient information to confidently assess the target.",
}


# ---------------------------------------------------------------------------
# Gemini prompt + call
# ---------------------------------------------------------------------------

LEVEL_INSTRUCTIONS = {
    "Beginner": (
        "Explain in simple, plain language. Avoid unnecessary cybersecurity "
        "jargon. Clearly explain what the VirusTotal and WHOIS results mean "
        "in everyday terms. Mention uncertainty and avoid claiming absolute "
        "safety."
    ),
    "Intermediate": (
        "Use moderate cybersecurity terminology. You may reference concepts "
        "such as reputation, detection engines, domain age, registrar, and "
        "suspicious indicators, briefly explaining each."
    ),
    "Advanced": (
        "Provide a more technical analysis. You may reference detection "
        "ratios, reputation signals, domain age indicators, infrastructure "
        "ownership, false positives, threat intelligence limitations, and "
        "confidence assessment, without over-explaining basic terms."
    ),
}


def build_gemini_prompt(target: str, target_type: str, level: str, results: list[dict]) -> str:
    """Build a prompt instructing Gemini to analyse only the supplied data."""
    lines = [
        "You are a cybersecurity assistant analysing threat intelligence data.",
        f"Target: {target}",
        f"Target type: {target_type}",
        f"User knowledge level: {level}",
        "",
        LEVEL_INSTRUCTIONS[level],
        "",
        "Collected intelligence data (this is the ONLY information you may use "
        "- do not invent facts or browse the internet):",
    ]

    for result in results:
        lines.append(f"\n--- {result['source']} ---")
        if result["success"]:
            lines.append(f"Status: success")
            lines.append(f"Data: {result['data']}")
        else:
            lines.append(f"Status: failed")
            lines.append(f"Error: {result['error']}")

    lines.append(
        "\nInstructions:\n"
        "1. Analyse only the supplied data above.\n"
        "2. Never claim that something is 100% safe.\n"
        "3. Clearly distinguish between safe indicators, suspicious "
        "indicators, and unknown/inconclusive information.\n"
        "4. Mention possible false positives.\n"
        "5. Explain limitations caused by missing data.\n"
        "6. Do not invent information not present above.\n"
        "7. Keep the response concise.\n\n"
        "Respond in exactly this structure:\n\n"
        "VERDICT:\n"
        "SAFE / SUSPICIOUS / MALICIOUS / UNKNOWN\n\n"
        "CONFIDENCE:\n"
        "Low / Medium / High\n\n"
        "KEY FINDINGS:\n"
        "- Finding 1\n"
        "- Finding 2\n"
        "- Finding 3\n\n"
        "AI INSIGHT:\n"
        "Short explanation appropriate for the selected knowledge level.\n\n"
        "LIMITATIONS:\n"
        "Brief explanation of missing or uncertain information."
    )

    return "\n".join(lines)


def call_gemini(prompt: str) -> tuple[bool, str]:
    """
    Call the Gemini API with the given prompt.
    Returns (success, text_or_error_message).
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return False, "AI analysis is unavailable because the Gemini API key is not configured."

    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        text = getattr(response, "text", None)
        if not text:
            return False, "Gemini returned an empty response."
        return True, text

    except Exception as exc:  # noqa: BLE001 - never let a Gemini error crash the app
        return False, f"AI analysis failed: {exc}"


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------

st.set_page_config(page_title="ThreadLens", page_icon="🛡️", layout="centered")

st.markdown("# 🛡️ ThreadLens")
st.caption("Lightweight threat intelligence for IPs, domains, and URLs.")
st.divider()

# --- Step 1: target type ---
target_type = st.radio(
    "What do you want to analyse?",
    options=["IP Address", "Domain", "URL"],
    horizontal=True,
)

# --- Step 2: target value ---
target = st.text_input(
    "Enter the target",
    placeholder=PLACEHOLDERS[target_type],
)

# --- Step 3: knowledge level ---
knowledge_level = st.select_slider(
    "Your cybersecurity knowledge level",
    options=["Beginner", "Intermediate", "Advanced"],
    value="Beginner",
)
st.caption("This only changes how the AI explains results - not what data is collected.")

analyse_clicked = st.button("🔍 Analyse", type="primary")

st.divider()

if analyse_clicked:
    validator = VALIDATORS[target_type]
    is_valid, message = validator(target)

    if not is_valid:
        st.error(message)
    else:
        # --- Collect intelligence dynamically from every registered source ---
        results = []
        with st.spinner("Collecting threat intelligence..."):
            for source_name, source_function in SOURCES.items():
                result = source_function(target, target_type)
                results.append(result)

        # --- Deterministic verdict from the collected evidence ---
        verdict, confidence = calculate_verdict(results)

        # --- Gemini insight (explanation only, not the verdict) ---
        with st.spinner("Generating AI insight..."):
            prompt = build_gemini_prompt(target, target_type, knowledge_level, results)
            gemini_success, gemini_text = call_gemini(prompt)

        # ------------------------------------------------------------------
        # 1. Target summary
        # ------------------------------------------------------------------
        st.subheader("Target Summary")
        st.text(f"Target: {target}")
        st.text(f"Type: {target_type}")
        st.text(f"Knowledge Level: {knowledge_level}")

        # ------------------------------------------------------------------
        # 2. Verdict card
        # ------------------------------------------------------------------
        icon, text_color, bg_color = VERDICT_STYLE[verdict]
        st.markdown(
            f"""
            <div style="background-color:{bg_color}; border-left: 6px solid {text_color};
                        padding: 16px; border-radius: 6px; margin: 12px 0;">
                <h2 style="color:{text_color}; margin:0;">{icon} {verdict}</h2>
                <p style="margin:4px 0 0 0;">Confidence: {confidence}</p>
                <p style="margin:4px 0 0 0; font-size: 0.9em;">{VERDICT_MEANING[verdict]}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # ------------------------------------------------------------------
        # 3. AI insight
        # ------------------------------------------------------------------
        st.subheader("🤖 AI Insight")
        if gemini_success:
            st.markdown(gemini_text)
        else:
            st.warning(gemini_text)

        # ------------------------------------------------------------------
        # 4. Intelligence sources (iterate dynamically - never hardcoded)
        # ------------------------------------------------------------------
        st.subheader("Intelligence Sources")
        for result in results:
            with st.expander(f"🔎 {result['source']}", expanded=True):
                if result["success"]:
                    st.markdown("**Status:** ✅ Success")
                    for key, value in result["data"].items():
                        label = key.replace("_", " ").title()
                        st.text(f"{label}: {value}")
                else:
                    st.markdown("**Status:** ❌ Failed")
                    st.text(result["error"])

        # ------------------------------------------------------------------
        # 5. Disclaimer
        # ------------------------------------------------------------------
        st.divider()
        st.caption(
            "⚠️ Threat intelligence results are indicators, not guarantees. "
            "A target with no detections may still be harmful, and automated "
            "detections can produce false positives."
        )
