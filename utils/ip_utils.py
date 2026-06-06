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
    if not (0 <= prefix <= 32):
        raise ValueError("Prefix must be between 0 and 32")
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def int_to_ip(x: int) -> str:
    """Convert a 32-bit integer to IPv4 string."""
    try:
        return str(ipaddress.IPv4Address(x))
    except (ValueError, ipaddress.AddressValueError):
        return ".".join(str((x >> i) & 0xFF) for i in (24, 16, 8, 0))