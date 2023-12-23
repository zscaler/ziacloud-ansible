from __future__ import absolute_import, division, print_function

__metaclass__ = type

from netaddr import IPAddress, IPNetwork, AddrFormatError


def validate_iso3166_alpha2(country_code):
    """
    Validates if the provided country code is a valid 2-letter ISO3166 Alpha2 code.

    :param country_code: 2-letter country code
    :return: True if valid, False otherwise
    """
    try:
        import pycountry
    except ImportError:
        raise ImportError(
            "The pycountry module is required to validate ISO3166 Alpha2 country codes."
        )

    try:
        country = pycountry.countries.get(alpha_2=country_code)
        return country is not None
    except AttributeError:
        return False


def deleteNone(_dict):
    """Delete None values recursively from all of the dictionaries, tuples, lists, sets"""
    if isinstance(_dict, dict):
        for key, value in list(_dict.items()):
            if isinstance(value, (list, dict, tuple, set)):
                _dict[key] = deleteNone(value)
            elif value is None or key is None:
                del _dict[key]
    elif isinstance(_dict, (list, set, tuple)):
        _dict = type(_dict)(deleteNone(item) for item in _dict if item is not None)
    return _dict


# Function to handle App Connector and Service Edge Group validations
def validate_latitude(val):
    try:
        v = float(val)
        if v < -90 or v > 90:
            return (None, ["latitude must be between -90 and 90"])
    except ValueError:
        return (None, ["latitude value should be a valid float number or not empty"])
    return (None, None)


def validate_longitude(val):
    try:
        v = float(val)
        if v < -180 or v > 180:
            return (None, ["longitude must be between -180 and 180"])
    except ValueError:
        return (None, ["longitude value should be a valid float number or not empty"])
    return (None, None)


def diff_suppress_func_coordinate(old, new):
    if old is None or new is None:
        return old == new
    try:
        o = round(float(old) * 1000000) / 1000000
        n = round(float(new) * 1000000) / 1000000
        return o == n
    except ValueError:
        return False


def is_valid_ipv4_or_range(value):
    try:
        if "-" in value:  # If it's a range
            start_ip, end_ip = value.split("-")
            start_ip = IPAddress(start_ip)
            end_ip = IPAddress(end_ip)
            return start_ip <= end_ip
        else:  # Single IP address
            IPAddress(value)
            return True
    except AddrFormatError:
        return False


def convert_to_minutes(time_value, time_unit):
    """
    Convert time value to minutes based on the time unit.
    """
    if time_unit == "HOUR":
        return time_value * 60
    elif time_unit == "DAY":
        return time_value * 60 * 24
    return time_value  # For MINUTE or undefined units, return as is


def validate_location_mgmt(location_mgmt):
    """
    Validate location management configuration based on given rules.
    """
    surrogate_ip = location_mgmt.get("surrogate_ip")
    idle_time_in_minutes = location_mgmt.get("idle_time_in_minutes")
    auth_required = location_mgmt.get("auth_required")
    surrogate_ip_enforced_for_known_browsers = location_mgmt.get(
        "surrogate_ip_enforced_for_known_browsers"
    )
    surrogate_refresh_time_in_minutes = location_mgmt.get(
        "surrogate_refresh_time_in_minutes"
    )
    surrogate_refresh_time_unit = location_mgmt.get("surrogate_refresh_time_unit")
    display_time_unit = location_mgmt.get("display_time_unit")

    # Rule 1: When surrogate_ip is true, idle_time_in_minutes must be set
    if surrogate_ip and idle_time_in_minutes is None:
        raise ValueError(
            "When 'surrogate_ip' is true, 'idle_time_in_minutes' must be set."
        )

    # Rule 2: idle_time_in_minutes must be within the range 1 to 720
    if idle_time_in_minutes is not None:
        if not 1 <= idle_time_in_minutes <= 720:
            raise ValueError(
                "'idle_time_in_minutes' must be within the range 1 to 720."
            )

    # Rule 3: When surrogate_ip and auth_required is true, surrogate_ip must also be set to true
    if surrogate_ip and not auth_required:
        raise ValueError(
            "Authentication required must be enabled when enabling surrogate IP."
        )

    # Rule 4: When surrogate_ip_enforced_for_known_browsers and surrogate_refresh_time_in_minutes,
    # surrogate_refresh_time_unit must be set, and surrogate_refresh_time_in_minutes must be within 1 to 720
    if (
        surrogate_ip_enforced_for_known_browsers
        and surrogate_refresh_time_in_minutes is not None
    ):
        if surrogate_refresh_time_unit is None:
            raise ValueError(
                "When 'surrogate_ip_enforced_for_known_browsers' and "
                "'surrogate_refresh_time_in_minutes' are set, 'surrogate_refresh_time_unit' "
                "must also be set."
            )
        if not 1 <= surrogate_refresh_time_in_minutes <= 720:
            raise ValueError(
                "'surrogate_refresh_time_in_minutes' must be within the range 1 to 720."
            )

    # New Rule: When surrogate_ip_enforced_for_known_browsers is true, surrogate_ip must be enabled
    if surrogate_ip_enforced_for_known_browsers and not surrogate_ip:
        raise ValueError(
            "Surrogate IP must be enabled when enforcing surrogate IP for known browsers."
        )

    # New Rule 1: surrogate_refresh_time_in_minutes cannot be greater than idle_time_in_minutes
    if surrogate_refresh_time_in_minutes and idle_time_in_minutes:
        if surrogate_refresh_time_in_minutes > idle_time_in_minutes:
            raise ValueError(
                "'surrogate_refresh_time_in_minutes' cannot be greater than 'idle_time_in_minutes'."
            )

    # New Rule 2: Validation based on surrogate_refresh_time_unit
    if surrogate_refresh_time_unit:
        if surrogate_refresh_time_unit not in ["HOUR", "MINUTE", "DAY"]:
            raise ValueError(
                "'surrogate_refresh_time_unit' must be one of HOUR, MINUTE, DAY."
            )

        if surrogate_refresh_time_unit == "HOUR" and (
            surrogate_refresh_time_in_minutes < 1
            or surrogate_refresh_time_in_minutes > 720
        ):
            raise ValueError(
                "For 'HOUR', 'surrogate_refresh_time_in_minutes' must be within 1 to 720."
            )

        if surrogate_refresh_time_unit == "MINUTE" and (
            surrogate_refresh_time_in_minutes < 1
            or surrogate_refresh_time_in_minutes > 43200
        ):
            raise ValueError(
                "For 'MINUTE', 'surrogate_refresh_time_in_minutes' must be within 1 to 43200."
            )

        if surrogate_refresh_time_unit == "DAY" and (
            surrogate_refresh_time_in_minutes < 1
            or surrogate_refresh_time_in_minutes > 30
        ):
            raise ValueError(
                "For 'DAY', 'surrogate_refresh_time_in_minutes' must be within 1 to 30."
            )

    # New Rule 3: Validation based on display_time_unit
    if display_time_unit:
        if display_time_unit not in ["HOUR", "MINUTE", "DAY"]:
            raise ValueError("'display_time_unit' must be one of HOUR, MINUTE, DAY.")

        if display_time_unit == "HOUR" and (
            idle_time_in_minutes < 1 or idle_time_in_minutes > 720
        ):
            raise ValueError(
                "For 'HOUR', 'idle_time_in_minutes' must be within 1 to 720."
            )

        if display_time_unit == "MINUTE" and (
            idle_time_in_minutes < 1 or idle_time_in_minutes > 43200
        ):
            raise ValueError(
                "For 'MINUTE', 'idle_time_in_minutes' must be within 1 to 43200."
            )

        if display_time_unit == "DAY" and (
            idle_time_in_minutes < 1 or idle_time_in_minutes > 30
        ):
            raise ValueError(
                "For 'DAY', 'idle_time_in_minutes' must be within 1 to 30."
            )

    # Convert idle_time_in_minutes based on display_time_unit
    display_time_unit = location_mgmt.get("display_time_unit")
    if idle_time_in_minutes is not None and display_time_unit:
        converted_idle_time = convert_to_minutes(
            idle_time_in_minutes, display_time_unit
        )
        location_mgmt["idle_time_in_minutes"] = converted_idle_time

        # Re-validate the converted idle_time_in_minutes
        if (
            not 1 <= converted_idle_time <= 43200
        ):  # Assuming 43200 as the max limit for a month in minutes
            raise ValueError(
                "'idle_time_in_minutes' converted value must be within the range 1 to 43200 minutes."
            )

    # Convert surrogate_refresh_time_in_minutes based on surrogate_refresh_time_unit
    if surrogate_refresh_time_in_minutes is not None and surrogate_refresh_time_unit:
        converted_surrogate_refresh_time = convert_to_minutes(
            surrogate_refresh_time_in_minutes, surrogate_refresh_time_unit
        )
        location_mgmt[
            "surrogate_refresh_time_in_minutes"
        ] = converted_surrogate_refresh_time

        # Re-validate the converted surrogate_refresh_time_in_minutes
        if (
            not 1 <= converted_surrogate_refresh_time <= 43200
        ):  # Assuming 43200 as the max limit for a month in minutes
            raise ValueError(
                "'surrogate_refresh_time_in_minutes' converted value must be within the range 1 to 43200 minutes."
            )

    aup_enabled = location_mgmt.get("aup_enabled")
    aup_timeout_in_days = location_mgmt.get("aup_timeout_in_days")
    caution_enabled = location_mgmt.get("caution_enabled")
    auth_required = location_mgmt.get("auth_required")

    # Rule: When aup_enabled is true, aup_timeout_in_days must be set within 1 to 180 days
    if aup_enabled and (
        aup_timeout_in_days is None or not 1 <= aup_timeout_in_days <= 180
    ):
        raise ValueError(
            "When 'aup_enabled' is true, 'aup_timeout_in_days' must be set within the range of 1 to 180 days."
        )

    # Rule: When caution_enabled is true, auth_required must be disabled
    if caution_enabled and auth_required:
        raise ValueError(
            "When 'caution_enabled' is set to true, 'auth_required' must be disabled."
        )

    # Validate IP addresses
    ip_addresses = location_mgmt.get("ip_addresses", [])
    for ip in ip_addresses:
        if not is_valid_ipv4_or_range(ip):
            raise ValueError(f"Invalid IPv4 address or range: {ip}")

    parent_id = location_mgmt.get("parent_id")
    ip_addresses = location_mgmt.get("ip_addresses", [])

    # New Rule: When parent_id is not 0, ip_addresses must not be empty
    if parent_id is not None and parent_id != 0 and not ip_addresses:
        raise ValueError("When 'parent_id' is not 0, 'ip_addresses' must not be empty.")
