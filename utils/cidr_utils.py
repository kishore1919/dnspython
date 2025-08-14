def calculate_usable_ips(prefix: int) -> int:
    """Calculate the number of usable IPs in a subnet based on CIDR prefix."""
    # Calculate total hosts in subnet: 2^(32-prefix)
    total_hosts = 1 << (32 - prefix)
    
    # Special cases: /31 (2 usable), /32 (1 host)
    usable = 2 if prefix == 31 else (1 if prefix == 32 else max(0, total_hosts - 2))
    return usable