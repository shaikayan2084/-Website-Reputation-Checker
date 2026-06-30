import socket

def check_dns(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        try:
            host = socket.gethostbyaddr(ip)
            reverse_dns = host[0]
        except:
            reverse_dns = "N/A"
        return {
            "success": True,
            "ip": ip,
            "reverse_dns": reverse_dns,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
