import ssl
import socket
from datetime import datetime, timezone


def check_ssl_certificate(domain: str):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                certificate = secure_sock.getpeercert()

        expires_on_text = certificate["notAfter"]
        expires_on = datetime.strptime(
            expires_on_text, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        days_left = (expires_on - datetime.now(timezone.utc)).days

        return {
            "name": "Security Certificate",
            "status": "Protected" if days_left > 30 else "Needs Attention",
            "message": (
                "Your website security certificate is valid."
                if days_left > 30
                else "Your website security certificate will expire soon."
            ),
            "days_left": days_left,
            "urgency": "No action needed" if days_left > 30 else "Renew soon",
            "advanced": {
                "expires_on": expires_on_text,
            },
        }

    except Exception as error:
        return {
            "name": "Security Certificate",
            "status": "Needs Attention",
            "message": "WebShield could not verify the website security certificate.",
            "urgency": "Check certificate setup",
            "advanced": {
                "error": str(error),
            },
        }