def lease_seconds_value(lease_minutes=None, lease_seconds=None, lease_days=None):
    supplied = [(lease_minutes, 60), (lease_seconds, 1), (lease_days, 86400)]
    supplied = [(value, factor) for value, factor in supplied if value is not None]
    if len(supplied) > 1:
        raise ValueError("Specify only one lease time unit")
    if not supplied:
        return None
    value, factor = supplied[0]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or (value == 0 and lease_days is None):
        raise ValueError("Lease time must be a positive integer")
    return value * factor
