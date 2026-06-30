import urllib.request, json

def check_blacklist(domain):
    results = {}
    threats = []

    # Google Safe Browsing (requires API key — skip if not configured)
    results["google_safe_browsing"] = {"checked": False, "note": "API key required"}

    # OpenPhish / PhishTank simulation — check common patterns
    suspicious_tlds = {".xyz", ".top", ".club", ".work", ".gq", ".ml", ".cf"}
    suspicious_keywords = ["login", "verify", "secure", "bank", "paypal", "account", "update"]

    flags = []
    ext = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    if ext in suspicious_tlds:
        flags.append("Suspicious TLD: " + ext)

    domain_lower = domain.lower()
    for kw in suspicious_keywords:
        if kw in domain_lower:
            flags.append("Contains '" + kw + "' in domain")
            break

    if flags:
        results["pattern_analysis"] = {"flagged": True, "flags": flags}
        threats.append("Pattern analysis found suspicious indicators")
    else:
        results["pattern_analysis"] = {"flagged": False, "flags": []}

    return {
        "results": results,
        "threats_found": len(threats),
        "threats": threats,
    }
