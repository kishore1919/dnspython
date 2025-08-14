import ipaddress


def is_valid_ipv4(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Check if a string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def subnet_mask_from_prefix(prefix: int) -> str:
    """Convert CIDR prefix to subnet mask."""
    if prefix == 0:
        return "0.0.0.0"
    bits = 0xFFFFFFFF << (32 - prefix)
    return int_to_ip(bits)


def int_to_ip(x: int) -> str:
    """Convert a 32-bit integer to IPv4 string."""
    return ".".join(str((x >> i) & 0xFF) for i in (24, 16, 8, 0))