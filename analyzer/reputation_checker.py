import socket

def check_ip_reputation(hostname):
    try:
        ip = socket.gethostbyname(hostname)
    except:
        return {"available": False, "error": "Could not resolve hostname"}

    checks = {}
    flags = []

    # Check if IP is private
    parts = ip.split(".")
    first = int(parts[0])
    is_private = (
        first == 10 or
        (first == 172 and 16 <= int(parts[1]) <= 31) or
        (first == 192 and parts[1] == "168") or
        first == 127
    )
    checks["is_private"] = is_private
    if is_private:
        flags.append("Private/local IP address")

    # Check if IP is from known hosting ranges (simplified)
    known_hosting = {
        "104": "Cloudflare",
        "151": "Google Cloud",
        "34":  "Google Cloud",
        "35":  "Google Cloud",
        "54":  "AWS",
        "13":  "AWS",
        "3":   "AWS",
        "52":  "AWS",
        "20":  "Azure",
        "40":  "Azure",
        "23":  "Akamai",
    }
    provider = known_hosting.get(parts[0])
    if provider:
        checks["hosting_provider"] = provider
    else:
        checks["hosting_provider"] = "Unknown / General"

    return {
        "available": True,
        "ip": ip,
        "checks": checks,
        "flags": flags,
    }
