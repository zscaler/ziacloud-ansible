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
module: zia_mobile_advanced_threat_settings
short_description: "Updates the Mobile Malware Protection rule information"
description:
  - "Updates the Mobile Malware Protection rule information"
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
  block_apps_with_malicious_activity:
    description: Blocks malicious or hidden applications
    type: bool
    required: false
  block_apps_with_known_vulnerabilities:
    description: Block app with known vulnerabilities or insecure modules
    type: bool
    required: false
  block_apps_sending_unencrypted_user_credentials:
    description: Block app leaking user credentials unencrypted
    type: bool
    required: false
  block_apps_sending_location_info:
    description: Block app leaking device location unencrypted for unknown purpose
    type: bool
    required: false
  block_apps_sending_personally_identifiable_info:
    description: Block app leaking PII unencrypted for unknown purpose
    type: bool
    required: false
  block_apps_sending_device_identifier:
    description: Block app leaking device IDs unencrypted or for unknown purposes
    type: bool
    required: false
  block_apps_communicating_with_ad_websites:
    description: Block app communicating with known ad websites
    type: bool
    required: false
  block_apps_communicating_with_remote_unknown_servers:
    description: Block app talking to unknown remote servers
    type: bool
    required: false
"""

EXAMPLES = r"""
- name: Updates the mobile malware protection policy configuration details
  zscaler.ziacloud.zia_mobile_advanced_threat_settings:
    provider: '{{ provider }}'
    block_apps_with_malicious_activity: true
    block_apps_with_known_vulnerabilities: true
    block_apps_sending_unencrypted_user_credentials: true
    block_apps_sending_location_info: true
    block_apps_sending_personally_identifiable_info: true
    block_apps_sending_device_identifier: true
    block_apps_communicating_with_ad_websites: true
    block_apps_communicating_with_remote_unknown_servers: true
"""

RETURN = r"""
#  Mobile Malware Protection Policy Configured.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    state = module.params.get("state")
    if state != "present":
        module.fail_json(msg="Only 'present' is supported for this module.")

    client = ZIAClientHelper(module)

    # Supported malware flags
    params = [
        "block_apps_with_malicious_activity",
        "block_apps_with_known_vulnerabilities",
        "block_apps_sending_unencrypted_user_credentials",
        "block_apps_sending_location_info",
        "block_apps_sending_personally_identifiable_info",
        "block_apps_sending_device_identifier",
        "block_apps_communicating_with_ad_websites",
        "block_apps_communicating_with_remote_unknown_servers",
    ]

    # Build the desired settings dict from user input
    settings_data = {k: module.params[k] for k in params if module.params.get(k) is not None}

    current_settings, _unused, error = client.mobile_threat_settings.get_mobile_advanced_settings()
    if error:
        module.fail_json(msg=f"Error fetching malware settings: {to_native(error)}")

    current_dict = current_settings.as_dict()

    drift = any(current_dict.get(k) != settings_data.get(k) for k in settings_data)

    module.warn(f"📦 Raw SDK response: {current_settings}")
    module.warn(f"📥 Desired settings: {settings_data}")
    module.warn(f"🧠 Drift detected: {drift}")

    if module.check_mode:
        module.exit_json(changed=drift, malware_settings=current_dict)

    if drift:
        updated, _unused, error = client.mobile_threat_settings.update_mobile_advanced_settings(**settings_data)
        if error:
            module.fail_json(msg=f"Error updating mobile advanced threat settings: {to_native(error)}")
        module.exit_json(changed=True, malware_settings=updated.as_dict())

    module.exit_json(changed=False, malware_settings=current_dict)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        block_apps_with_malicious_activity=dict(type="bool", required=False),
        block_apps_with_known_vulnerabilities=dict(type="bool", required=False),
        block_apps_sending_unencrypted_user_credentials=dict(type="bool", required=False),
        block_apps_sending_location_info=dict(type="bool", required=False),
        block_apps_sending_personally_identifiable_info=dict(type="bool", required=False),
        block_apps_sending_device_identifier=dict(type="bool", required=False),
        block_apps_communicating_with_ad_websites=dict(type="bool", required=False),
        block_apps_communicating_with_remote_unknown_servers=dict(type="bool", required=False),
        state=dict(type="str", choices=["present"], default="present"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
