import ssl, socket, datetime

def check_ssl(hostname):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                remaining_days = (not_after - now).days
                return {
                    "valid": True,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "common_name": subject.get("commonName", ""),
                    "issued": not_before.strftime("%Y-%m-%d"),
                    "expires": not_after.strftime("%Y-%m-%d"),
                    "days_remaining": remaining_days,
                    "expired": remaining_days < 0,
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}
