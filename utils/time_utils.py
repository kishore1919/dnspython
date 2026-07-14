import datetime


def get_current_time() -> str:
    """Get current local time as a formatted string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_current_second() -> int:
    """Get current second (0-59)."""
    return datetime.datetime.now().second


def convert_railway_to_ampm(time_str: str) -> str:
    """Convert railway time (24-hour format) to am/pm format.

    Args:
        time_str: Time string in format "HH:MM:SS" (24-hour format)

    Returns:
        Time string in format "H:MM:SS AM/PM" (12-hour format)

    Examples:
        >>> convert_railway_to_ampm("14:30:00")
        '2:30:00 PM'
        >>> convert_railway_to_ampm("09:15:00")
        '9:15:00 AM'
        >>> convert_railway_to_ampm("00:45:00")
        '12:45:00 AM'
        >>> convert_railway_to_ampm("12:00:00")
        '12:00:00 PM'
    """
    try:
        # Parse the time string
        hour_str, minute_str, second_str = time_str.split(":")
        hour = int(hour_str)
        minute = int(minute_str)
        second = int(second_str)

        # Validate ranges
        if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
            raise ValueError(f"Invalid time: {time_str}")

        # Determine AM/PM and convert hour
        period = "AM" if hour < 12 else "PM"

        # Convert 24-hour to 12-hour format
        if hour == 0:
            hour_12 = 12  # Midnight
        elif hour > 12:
            hour_12 = hour - 12
        else:
            hour_12 = hour  # 1-12 (except 0 which is 12)

        # Format with leading zeros for minutes and seconds
        return f"{hour_12}:{minute_str:0>2}:{second_str:0>2} {period}"

    except ValueError as e:
        raise ValueError(f"Invalid time format: {time_str}. Expected HH:MM:SS") from e