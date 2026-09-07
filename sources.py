"""
sources.py
----------
This file is responsible ONLY for collecting threat intelligence data.

Rules for this file (do not break these when extending it):
- No Streamlit imports or UI code here.
- No calls to Gemini here.
- No "verdict" decisions here - just collect and normalize data.
- Every function returns the same dictionary shape (see below), so
  app.py can process any source generically without knowing its
  internal details.

Return format (always):
{
    "source": "SourceName",
    "success": True/False,
    "data": {...},      # normalized, human-friendly fields
    "error": None/"message"
}

HOW TO ADD A NEW SOURCE:
1. Write a new function, e.g. get_abuseipdb(target, target_type), that
   follows the same signature and return format as the ones below.
2. Register it in the SOURCES dictionary at the bottom of this file:
       SOURCES["AbuseIPDB"] = get_abuseipdb
That's it. app.py loops over SOURCES automatically, so your new source
will be called, displayed, and included in the Gemini prompt without
touching any other file.
"""

import os
import requests
import whois  # from the python-whois package


# Default network timeout (seconds) for all outbound requests.
REQUEST_TIMEOUT = 10


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def get_virustotal(target: str, target_type: str) -> dict:
    """
    Query VirusTotal for an IP address, domain, or URL.

    Returns a normalized summary of detection counts and a few useful
    metadata fields, rather than the full raw API response.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {
            "source": "VirusTotal",
            "success": False,
            "data": {},
            "error": "VirusTotal API key is not configured.",
        }

    headers = {"x-apikey": api_key}

    try:
        if target_type == "IP Address":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        elif target_type == "Domain":
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        elif target_type == "URL":
            # VirusTotal requires URLs to be submitted, then looked up by
            # a URL-safe base64-encoded ID (without padding).
            import base64

            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            lookup_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            resp = requests.get(lookup_url, headers=headers, timeout=REQUEST_TIMEOUT)

            # If VirusTotal has never seen this URL before, submit it for
            # a fresh analysis instead of returning a 404.
            if resp.status_code == 404:
                submit_resp = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": target},
                    timeout=REQUEST_TIMEOUT,
                )
                if submit_resp.status_code not in (200, 201):
                    return {
                        "source": "VirusTotal",
                        "success": False,
                        "data": {},
                        "error": "Could not submit URL for analysis.",
                    }
                # Freshly submitted URLs may not have analysis results yet.
                return {
                    "source": "VirusTotal",
                    "success": True,
                    "data": {
                        "note": (
                            "URL was newly submitted to VirusTotal and has "
                            "not been fully analysed yet. Results may be "
                            "incomplete."
                        )
                    },
                    "error": None,
                }
        else:
            return {
                "source": "VirusTotal",
                "success": False,
                "data": {},
                "error": f"Unsupported target type: {target_type}",
            }

        if resp.status_code == 401:
            return {
                "source": "VirusTotal",
                "success": False,
                "data": {},
                "error": "VirusTotal rejected the API key (unauthorized).",
            }
        if resp.status_code == 429:
            return {
                "source": "VirusTotal",
                "success": False,
                "data": {},
                "error": "VirusTotal rate limit reached. Try again later.",
            }
        if resp.status_code != 200:
            return {
                "source": "VirusTotal",
                "success": False,
                "data": {},
                "error": f"VirusTotal returned status {resp.status_code}.",
            }

        payload = resp.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        normalized = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories"),
        }

        return {
            "source": "VirusTotal",
            "success": True,
            "data": normalized,
            "error": None,
        }

    except requests.exceptions.Timeout:
        return {
            "source": "VirusTotal",
            "success": False,
            "data": {},
            "error": "VirusTotal request timed out.",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "source": "VirusTotal",
            "success": False,
            "data": {},
            "error": f"Network error contacting VirusTotal: {exc}",
        }
    except Exception as exc:  # noqa: BLE001 - keep the app from crashing
        return {
            "source": "VirusTotal",
            "success": False,
            "data": {},
            "error": f"Unexpected error: {exc}",
        }


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def get_whois(target: str, target_type: str) -> dict:
    """
    Retrieve WHOIS registration information for a domain, or (best-effort)
    network registration info for an IP address / a URL's hostname.

    WHOIS data is inconsistent across registrars, so every field is
    fetched defensively and missing data is simply omitted rather than
    causing an error.
    """
    # WHOIS operates on hostnames, so for a URL we extract the hostname.
    lookup_target = target
    if target_type == "URL":
        from urllib.parse import urlparse

        parsed = urlparse(target)
        lookup_target = parsed.hostname or target

    try:
        record = whois.whois(lookup_target)

        if not record or not getattr(record, "domain_name", None):
            return {
                "source": "WHOIS",
                "success": False,
                "data": {},
                "error": "No WHOIS data found (registration may be private "
                         "or the lookup type is unsupported).",
            }

        def _first(value):
            """WHOIS fields sometimes come back as lists - take the first."""
            if isinstance(value, list):
                return value[0] if value else None
            return value

        normalized = {
            "registrar": _first(getattr(record, "registrar", None)),
            "created": str(_first(getattr(record, "creation_date", None))) or None,
            "expires": str(_first(getattr(record, "expiration_date", None))) or None,
            "updated": str(_first(getattr(record, "updated_date", None))) or None,
            "organization": _first(getattr(record, "org", None)),
            "name_servers": getattr(record, "name_servers", None),
        }
        # Drop empty/None fields for a cleaner display.
        normalized = {k: v for k, v in normalized.items() if v}

        if not normalized:
            return {
                "source": "WHOIS",
                "success": False,
                "data": {},
                "error": "WHOIS lookup succeeded but returned no usable "
                         "fields (registration may be private).",
            }

        return {
            "source": "WHOIS",
            "success": True,
            "data": normalized,
            "error": None,
        }

    except Exception as exc:  # noqa: BLE001 - WHOIS libraries throw many types
        return {
            "source": "WHOIS",
            "success": False,
            "data": {},
            "error": f"WHOIS lookup failed: {exc}",
        }


# ---------------------------------------------------------------------------
# Source Registry
# ---------------------------------------------------------------------------
# app.py loops over this dictionary to call every registered source.
# To add a new source, define a function above (or in a new file you
# import from) and add one line here.

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
