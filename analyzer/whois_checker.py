try:
    import whois as whois_module
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

def check_whois(domain):
    if not HAS_WHOIS:
        return {"available": False, "error": "python-whois not installed"}
    try:
        w = whois_module.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        expires = w.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        result = {
            "available": True,
            "registrar": w.registrar or "Unknown",
            "created": str(created) if created else "Unknown",
            "expires": str(expires) if expires else "Unknown",
        }
        if created:
            age_days = (__import__("datetime").datetime.now(created.tzinfo) - created).days
            result["age_days"] = age_days
            result["age_years"] = round(age_days / 365.25, 1)
        return result
    except Exception as e:
        return {"available": False, "error": str(e)}
