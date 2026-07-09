import logging
from typing import Callable

import requests

from .ip_utils import is_valid_ipv4, is_valid_ipv6

logger = logging.getLogger("dnspython.ip_fetch")


def _fetch_ip(
    services: list[str],
    validator: Callable[[str], bool],
    fallback: str,
    label: str,
) -> str:
    """Try each service in order, returning the first valid IP, else fallback."""
    for service in services:
        try:
            response = requests.get(service, timeout=5)
            ip = response.text.strip()
            if validator(ip):
                logger.info("%s fetched from %s: %s", label, service, ip)
                return ip
        except Exception as e:
            logger.warning("Failed to fetch %s from %s: %s", label, service, e)
            continue

    logger.warning("Using %s fallback: %s", label, fallback)
    return fallback


_IPV4_SERVICES = [
    "https://ipv4.icanhazip.com",
    "https://api.ipify.org",
    "https://v4.ident.me",
    "https://ipecho.net/plain",
]

_IPV6_SERVICES = [
    "https://ipv6.icanhazip.com",
    "https://v6.ident.me",
]


def fetch_ipv4() -> str:
    """Fetch public IPv4 address."""
    return _fetch_ip(_IPV4_SERVICES, is_valid_ipv4, "127.0.0.1", "IPv4")


def fetch_ipv6() -> str:
    """Fetch public IPv6 address."""
    return _fetch_ip(_IPV6_SERVICES, is_valid_ipv6, "::1", "IPv6")