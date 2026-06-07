import logging
import requests
from .ip_utils import is_valid_ipv4, is_valid_ipv6

logger = logging.getLogger("dnspython.ip_fetch")


def fetch_ipv4() -> str:
    """Fetch public IPv4 address."""
    services = [
        "https://ipv4.icanhazip.com",
        "https://api.ipify.org",
        "https://v4.ident.me",
        "https://ipecho.net/plain"
    ]
    
    for service in services:
        try:
            response = requests.get(service, timeout=5)
            ip = response.text.strip()
            if is_valid_ipv4(ip):
                logger.info("IPv4 fetched from %s: %s", service, ip)
                return ip
        except Exception as e:
            logger.warning("Failed to fetch IPv4 from %s: %s", service, e)
            continue
    
    logger.warning("Using IPv4 fallback: 127.0.0.1")
    return "127.0.0.1"  # Fallback


def fetch_ipv6() -> str:
    """Fetch public IPv6 address."""
    services = [
        "https://ipv6.icanhazip.com",
        "https://v6.ident.me"
    ]
    
    for service in services:
        try:
            response = requests.get(service, timeout=5)
            ip = response.text.strip()
            if is_valid_ipv6(ip):
                logger.info("IPv6 fetched from %s: %s", service, ip)
                return ip
        except Exception as e:
            logger.warning("Failed to fetch IPv6 from %s: %s", service, e)
            continue
    
    logger.warning("Using IPv6 fallback: ::1")
    return "::1"  # Fallback