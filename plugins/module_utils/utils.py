# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

#                              MIT License
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import missing_required_lib
import re
from datetime import datetime

try:
    from netaddr import IPAddress, AddrFormatError

    HAS_NETADDR = True
    ADDR_IMPORT_ERROR = None  # Set to None when import is successful
except ImportError:
    IPAddress = None  # Setting to None to indicate unavailability
    HAS_NETADDR = False
    ADDR_IMPORT_ERROR = missing_required_lib("netaddr")  # Store the error for reporting


try:
    import pytz

    HAS_PYTZ = True
    PYTZ_IMPORT_ERROR = None
except ImportError:
    pytz = None
    HAS_PYTZ = False
    PYTZ_IMPORT_ERROR = missing_required_lib("pytz")


try:
    from babel.core import Locale, UnknownLocaleError

    HAS_BABEL = True
    BABEL_IMPORT_ERROR = None
except ImportError:
    Locale = None
    UnknownLocaleError = None
    HAS_BABEL = False
    BABEL_IMPORT_ERROR = "The 'babel' module is required. Please install it using 'pip install Babel'."


def to_snake_case(string):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", string).lower()


def convert_keys_to_snake_case(data):
    if isinstance(data, dict):
        return {to_snake_case(k): convert_keys_to_snake_case(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_keys_to_snake_case(i) for i in data]
    return data


def validate_iso3166_alpha2(country_code):
    """
    Validates if the provided country code is a valid 2-letter ISO3166 Alpha2 code.

    :param country_code: 2-letter country code
    :return: True if valid, False otherwise
    """
    try:
        import pycountry
    except ImportError:
        raise ImportError("The pycountry module is required to validate ISO3166 Alpha2 country codes.")

    try:
        country = pycountry.countries.get(alpha_2=country_code)
        return country is not None
    except AttributeError:
        return False


def validate_locale_code(locale):
    """
    Validates whether a locale string is BCP 47-compliant (e.g., en-US, fr-FR, zh-CN).
    Returns True if valid, False otherwise.
    """
    if not HAS_BABEL:
        raise ImportError(BABEL_IMPORT_ERROR)

    try:
        # Babel expects underscores like 'en_US', but we allow hyphen input like 'en-US'
        Locale.parse(locale.replace("-", "_"))
        return True
    except (UnknownLocaleError, ValueError):
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
    if not HAS_NETADDR:
        raise ImportError(ADDR_IMPORT_ERROR)  # Raise the captured ImportError if netaddr is missing

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


def parse_rfc1123_to_epoch_millis(date_str):
    """
    Convert an RFC1123 or friendly date string to epoch milliseconds.
    Example accepted: "Mon, 02 Jan 2006 15:04:05 UTC"
    """
    if not HAS_PYTZ:
        raise ImportError(PYTZ_IMPORT_ERROR)

    try:
        dt = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %Z")
        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)
        return int(dt.timestamp() * 1000)
    except Exception as e:
        raise ValueError(f"Failed to parse date '{date_str}'. Ensure it's in RFC1123 format like 'Mon, 02 Jan 2006 15:04:05 UTC'. Error: {e}")


def validate_location_mgmt(location_mgmt):
    """
    Validate location management configuration based on given rules.
    """
    # Default setting for ip_addresses to avoid TypeError on iteration
    ip_addresses = location_mgmt.get("ip_addresses", [])
    parent_id = location_mgmt.get("parent_id")

    surrogate_ip = location_mgmt.get("surrogate_ip")
    idle_time_in_minutes = location_mgmt.get("idle_time_in_minutes")
    auth_required = location_mgmt.get("auth_required")
    surrogate_ip_enforced_for_known_browsers = location_mgmt.get("surrogate_ip_enforced_for_known_browsers")
    surrogate_refresh_time_in_minutes = location_mgmt.get("surrogate_refresh_time_in_minutes")
    surrogate_refresh_time_unit = location_mgmt.get("surrogate_refresh_time_unit")
    display_time_unit = location_mgmt.get("display_time_unit")

    # Rule 1: When surrogate_ip is true, idle_time_in_minutes must be set
    if surrogate_ip and idle_time_in_minutes is None:
        raise ValueError("When 'surrogate_ip' is true, 'idle_time_in_minutes' must be set.")

    # Rule 2: idle_time_in_minutes must be within the range 1 to 720
    if idle_time_in_minutes is not None:
        if not 1 <= idle_time_in_minutes <= 720:
            raise ValueError("'idle_time_in_minutes' must be within the range 1 to 720.")

    # Rule 3: When surrogate_ip and auth_required is true, surrogate_ip must also be set to true
    if surrogate_ip and not auth_required:
        raise ValueError("Authentication required must be enabled when enabling surrogate IP.")

    # Rule 4: When surrogate_ip_enforced_for_known_browsers and surrogate_refresh_time_in_minutes,
    # surrogate_refresh_time_unit must be set, and surrogate_refresh_time_in_minutes must be within 1 to 720
    if surrogate_ip_enforced_for_known_browsers and surrogate_refresh_time_in_minutes is not None:
        if surrogate_refresh_time_unit is None:
            raise ValueError(
                "When 'surrogate_ip_enforced_for_known_browsers' and "
                "'surrogate_refresh_time_in_minutes' are set, 'surrogate_refresh_time_unit' "
                "must also be set."
            )
        if not 1 <= surrogate_refresh_time_in_minutes <= 720:
            raise ValueError("'surrogate_refresh_time_in_minutes' must be within the range 1 to 720.")

    # New Rule: When surrogate_ip_enforced_for_known_browsers is true, surrogate_ip must be enabled
    if surrogate_ip_enforced_for_known_browsers and not surrogate_ip:
        raise ValueError("Surrogate IP must be enabled when enforcing surrogate IP for known browsers.")

    # New Rule 1: surrogate_refresh_time_in_minutes cannot be greater than idle_time_in_minutes
    if surrogate_refresh_time_in_minutes and idle_time_in_minutes:
        if surrogate_refresh_time_in_minutes > idle_time_in_minutes:
            raise ValueError("'surrogate_refresh_time_in_minutes' cannot be greater than 'idle_time_in_minutes'.")

    # New Rule 2: Validation based on surrogate_refresh_time_unit
    if surrogate_refresh_time_unit:
        if surrogate_refresh_time_unit not in ["HOUR", "MINUTE", "DAY"]:
            raise ValueError("'surrogate_refresh_time_unit' must be one of HOUR, MINUTE, DAY.")

        if surrogate_refresh_time_unit == "HOUR" and (surrogate_refresh_time_in_minutes < 1 or surrogate_refresh_time_in_minutes > 720):
            raise ValueError("For 'HOUR', 'surrogate_refresh_time_in_minutes' must be within 1 to 720.")

        if surrogate_refresh_time_unit == "MINUTE" and (surrogate_refresh_time_in_minutes < 1 or surrogate_refresh_time_in_minutes > 43200):
            raise ValueError("For 'MINUTE', 'surrogate_refresh_time_in_minutes' must be within 1 to 43200.")

        if surrogate_refresh_time_unit == "DAY" and (surrogate_refresh_time_in_minutes < 1 or surrogate_refresh_time_in_minutes > 30):
            raise ValueError("For 'DAY', 'surrogate_refresh_time_in_minutes' must be within 1 to 30.")

    # New Rule 3: Validation based on display_time_unit
    if display_time_unit:
        if display_time_unit not in ["HOUR", "MINUTE", "DAY"]:
            raise ValueError("'display_time_unit' must be one of HOUR, MINUTE, DAY.")

        if display_time_unit == "HOUR" and (idle_time_in_minutes < 1 or idle_time_in_minutes > 720):
            raise ValueError("For 'HOUR', 'idle_time_in_minutes' must be within 1 to 720.")

        if display_time_unit == "MINUTE" and (idle_time_in_minutes < 1 or idle_time_in_minutes > 43200):
            raise ValueError("For 'MINUTE', 'idle_time_in_minutes' must be within 1 to 43200.")

        if display_time_unit == "DAY" and (idle_time_in_minutes < 1 or idle_time_in_minutes > 30):
            raise ValueError("For 'DAY', 'idle_time_in_minutes' must be within 1 to 30.")

    # Convert idle_time_in_minutes based on display_time_unit
    display_time_unit = location_mgmt.get("display_time_unit")
    if idle_time_in_minutes is not None and display_time_unit:
        converted_idle_time = convert_to_minutes(idle_time_in_minutes, display_time_unit)
        location_mgmt["idle_time_in_minutes"] = converted_idle_time

        # Re-validate the converted idle_time_in_minutes
        if not 1 <= converted_idle_time <= 43200:  # Assuming 43200 as the max limit for a month in minutes
            raise ValueError("'idle_time_in_minutes' converted value must be within the range 1 to 43200 minutes.")

    # Convert surrogate_refresh_time_in_minutes based on surrogate_refresh_time_unit
    if surrogate_refresh_time_in_minutes is not None and surrogate_refresh_time_unit:
        converted_surrogate_refresh_time = convert_to_minutes(surrogate_refresh_time_in_minutes, surrogate_refresh_time_unit)
        location_mgmt["surrogate_refresh_time_in_minutes"] = converted_surrogate_refresh_time

        # Re-validate the converted surrogate_refresh_time_in_minutes
        if not 1 <= converted_surrogate_refresh_time <= 43200:  # Assuming 43200 as the max limit for a month in minutes
            raise ValueError("'surrogate_refresh_time_in_minutes' converted value must be within the range 1 to 43200 minutes.")

    aup_enabled = location_mgmt.get("aup_enabled")
    aup_timeout_in_days = location_mgmt.get("aup_timeout_in_days")
    caution_enabled = location_mgmt.get("caution_enabled")
    auth_required = location_mgmt.get("auth_required")

    # Rule: When aup_enabled is true, aup_timeout_in_days must be set within 1 to 180 days
    if aup_enabled and (aup_timeout_in_days is None or not 1 <= aup_timeout_in_days <= 180):
        raise ValueError("When 'aup_enabled' is true, 'aup_timeout_in_days' must be set within the range of 1 to 180 days.")

    # Rule: When caution_enabled is true, auth_required must be disabled
    if caution_enabled and auth_required:
        raise ValueError("When 'caution_enabled' is set to true, 'auth_required' must be disabled.")

    # Check VPN credentials to determine if IP addresses need to be validated for IP type VPN
    validate_ips = False
    vpn_credentials = location_mgmt.get("vpn_credentials", [])
    for cred in vpn_credentials:
        if cred.get("type") == "IP":
            validate_ips = True
            break

    # Validate IP addresses only if necessary:
    if validate_ips:
        if not ip_addresses:  # This checks if IP addresses are provided when needed
            raise ValueError("IP addresses must be provided for IP type VPN credentials.")
        for ip in ip_addresses:
            if not is_valid_ipv4_or_range(ip):
                raise ValueError(f"Invalid IPv4 address or range: {ip}")

    # Rule for parent_id and ip_addresses:
    # Validate ip_addresses are provided if parent_id is not None and not 0 (indicating a sub-location)
    if parent_id is not None and parent_id != 0:
        if not ip_addresses:
            raise ValueError("When 'parent_id' is not 0, 'ip_addresses' must not be empty.")


# This function is used by the Location Management to distinguish
# Between VPN Type IP and UFQDN
def process_vpn_credentials(vpn_creds):
    if not vpn_creds:
        return []
    processed_creds = []
    for cred in vpn_creds:
        if cred["type"] == "UFQDN":
            # For UFQDN, ensure 'fqdn' is provided and ignore 'ip_address'
            if "fqdn" not in cred or not cred["fqdn"]:
                raise ValueError("FQDN must be provided for UFQDN VPN credentials")
            processed_creds.append(
                {
                    "id": cred.get("id"),
                    "type": "UFQDN",
                    "fqdn": cred["fqdn"],
                    "pre_shared_key": cred.get("pre_shared_key"),
                }
            )
        elif cred["type"] == "IP":
            # For IP, ensure 'ip_address' is provided
            if "ip_address" not in cred or not cred["ip_address"]:
                raise ValueError("IP address must be provided for IP VPN credentials")
            processed_creds.append(
                {
                    "id": cred.get("id"),
                    "type": "IP",
                    "ip_address": cred["ip_address"],
                    "pre_shared_key": cred.get("pre_shared_key"),
                }
            )
    return processed_creds


def normalize_list(values):
    """
    Normalize a list of strings by stripping whitespace, lowering case, removing duplicates, and sorting.

    Args:
        values (list): The list to normalize

    Returns:
        list: A cleaned, sorted list of unique values
    """
    if not isinstance(values, list):
        return []
    return sorted(set([v.strip().lower() for v in values if isinstance(v, str) and v.strip()]))


# Utility Function: normalize_boolean_attributes
def normalize_boolean_attributes(rule, bool_attributes):
    """
    Ensures that boolean attributes in the rule are normalized.
    If the attribute is None, it will be set to False.

    Args:
        rule (dict): The rule dictionary containing attributes.
        bool_attributes (list): List of attribute names that should be treated as boolean.

    Returns:
        dict: The rule with normalized boolean attributes.
    """
    for attr in bool_attributes:
        if rule.get(attr) is None:
            rule[attr] = False
    return rule


# def collect_all_items(list_fn, query_params=None):
#     """
#     Collects all pages of results from a paginated ZIA SDK list_* method.
#     """
#     items, resp, err = list_fn(query_params)
#     if err:
#         return None, err

#     all_items = items or []
#     while resp and resp.has_next():
#         page, err = resp.next()
#         if err:
#             return None, err
#         if page:
#             all_items.extend(page)

#     return all_items, None


def collect_all_items(list_fn, query_params=None):
    """
    Collects all pages of results from a paginated ZPA SDK list_* method.
    Handles both paginated and non-paginated SDK methods.
    """
    result = list_fn(query_params)

    # Case 1: (items, error) – non-paginated SDK methods
    if isinstance(result, tuple) and len(result) == 2:
        items, err = result
        if err:
            return None, err
        return items or [], None

    # Case 2: (items, resp, error) – paginated SDK methods
    if isinstance(result, tuple) and len(result) == 3:
        items, resp, err = result
        if err:
            return None, err

        all_items = items or []
        while resp and resp.has_next():
            page, resp, err = resp.next()  # ✅ unpack all 3
            if err:
                return None, err
            if page:
                all_items.extend(page)

        return all_items, None

    return None, f"Unexpected return structure from {list_fn.__name__}"


def preprocess_rule(rule, params):
    for attr in params:
        if attr in rule and rule[attr] is not None:
            if isinstance(rule[attr], list):
                if all(isinstance(item, dict) and "id" in item for item in rule[attr]):
                    rule[attr] = [item["id"] for item in rule[attr]]
                else:
                    rule[attr] = sorted(rule[attr])
    return rule
