import datetime


def get_current_time() -> str:
    """Get current local time as a formatted string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_current_second() -> int:
    """Get current second (0-59)."""
    return datetime.datetime.now().second