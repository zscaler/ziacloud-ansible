#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

#                             MIT License
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

DOCUMENTATION = r"""
---
module: zia_remote_assistance
short_description: "Retrieves information about the Remote Assistance "
description:
  - "Retrieves information about the Remote Assistance option configured in the ZIA Admin Portal"
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.modified_state

options:
  view_only_until:
    description:
        - The time until when view-only access is granted.
        - Use RFC 1123 format i.e Tue, 15 Apr 2025 12:00:00 UTC
    type: str
    required: false
  full_access_until:
    description:
        - The time until when full-access is granted.
        - Use RFC 1123 format i.e Tue, 15 Apr 2025 12:00:00 UTC
    required: false
    type: str
  username_obfuscated:
    description: "The rule label name."
    required: false
    type: bool
  device_info_obfuscate:
    description: "The rule label name."
    required: false
    type: bool
"""

EXAMPLES = r"""
- name: Configure Remote Assistance
  zscaler.ziacloud.zia_remote_assistance:
    provider: '{{ provider }}'
    view_only_until: "Tue, 15 Apr 2025 12:00:00 UTC"
    full_access_until: "Tue, 15 Apr 2025 13:00:00 UTC"
    username_obfuscated: true
    device_info_obfuscate: true
"""

RETURN = r"""
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
    parse_rfc1123_to_epoch_millis,
)
from datetime import datetime, timezone


def normalize_eun_values(data: dict) -> dict:
    """Normalize current and desired EUN values by removing computed fields and empty strings."""
    if not data:
        return {}

    result = {}
    for k, v in data.items():
        if isinstance(v, str) and v.strip() == "":
            continue  # Skip blank strings
        result[k] = v
    return result


def core(module):
    state = module.params.get("state")
    if state != "present":
        module.fail_json(msg="Only 'present' is supported for this module.")

    client = ZIAClientHelper(module)

    # Define all valid fields supported in the EUN payload
    params = [
        "view_only_until",
        "full_access_until",
        "username_obfuscated",
        "device_info_obfuscate",
    ]

    settings_data = {
        k: module.params.get(k)
        for k in params
        if module.params.get(k) is not None and not (isinstance(module.params.get(k), str) and module.params.get(k).strip() == "")
    }

    for date_field in ["view_only_until", "full_access_until"]:
        value = settings_data.get(date_field)
        if isinstance(value, str):
            try:
                timestamp = parse_rfc1123_to_epoch_millis(value)
                now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
                if timestamp < now_ms:
                    module.fail_json(msg=f"The value for '{date_field}' must be a future date. Provided: {value}")
                settings_data[date_field] = timestamp
            except ValueError as ve:
                module.fail_json(msg=str(ve))

    # 1) Fetch current EUN settings from the SDK
    current_settings, _unused, error = client.remote_assistance.get_remote_assistance()
    if error:
        module.fail_json(msg=f"Error fetching remote assistance settings: {to_native(error)}")

    # 2) Convert both current/desired data to normalized dicts
    current_dict = normalize_eun_values(current_settings.as_dict())
    desired_dict = normalize_eun_values(settings_data)

    module.warn(f"🧪 Raw keys from SDK: {list(current_dict.keys())}")
    module.warn(f"🔍 Current settings: {current_dict}")
    module.warn(f"📅 Desired settings: {desired_dict}")

    # 3) Identify which keys differ in the final comparison
    diff_keys = []
    for k in desired_dict:
        if current_dict.get(k) != desired_dict.get(k):
            diff_keys.append(k)

    drift = bool(diff_keys)
    module.warn(f"🧠 Drift detected: {drift}")

    if drift:
        module.warn("🔎 Drift found in these keys:")
        for k in diff_keys:
            module.warn(f"  {k}: current={current_dict.get(k)}, desired={desired_dict.get(k)}")

    # 4) Respect check_mode
    if module.check_mode:
        module.exit_json(changed=drift)

    # 5) If drift, update the resource
    if drift:
        # Update current settings object with the desired values
        for k, v in desired_dict.items():
            setattr(current_settings, k, v)

        # Convert the updated object to a request payload
        payload = deleteNone(current_settings.as_dict())

        for k, v in payload.items():
            setattr(current_settings, k, v)

        module.warn(f"🧼 Cleaned payload sent to SDK: {payload}")

        updated, _unused, error = client.remote_assistance.update_remote_assistance(**payload)
        if error:
            module.fail_json(msg=f"Error updating remote assistance settings: {to_native(error)}")

        module.exit_json(changed=True, end_user_notifications=updated.as_dict())
    else:
        module.exit_json(changed=False, msg="No drift detected; nothing to update.")


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            view_only_until=dict(type="str", required=False),
            full_access_until=dict(type="str", required=False),
            username_obfuscated=dict(type="bool", required=False),
            device_info_obfuscate=dict(type="bool", required=False),
            state=dict(type="str", choices=["present"], default="present"),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
