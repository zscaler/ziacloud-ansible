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
module: zia_cloud_app_control_rules_info
short_description: Gets the list of cloud application rules by the type of rule..
description: Gets the list of cloud application rules by the type of rule..
author:
  - William Guilherme (@willguibr)
version_added: "1.3.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  id:
    description:
        - The universally unique identifier (UUID) for the browser isolation profile.
    type: str
    required: false
  name:
    description:
        - Name of the cloud application control rule.
    required: false
    type: str
  rule_type:
    description:
        - The rule type selected from the available options.
    required: true
    type: str
    choices:
      - SOCIAL_NETWORKING
      - STREAMING_MEDIA
      - WEBMAIL
      - INSTANT_MESSAGING
      - BUSINESS_PRODUCTIVITY
      - ENTERPRISE_COLLABORATION
      - SALES_AND_MARKETING
      - SYSTEM_AND_DEVELOPMENT
      - CONSUMER
      - HOSTING_PROVIDER
      - IT_SERVICES
      - FILE_SHARE
      - DNS_OVER_HTTPS
      - HUMAN_RESOURCES
      - LEGAL
      - HEALTH_CARE
      - FINANCE
      - CUSTOM_CAPP
      - AI_ML
"""

EXAMPLES = r"""
- name: Gather Information Details of a cloud application control rule by Name
  zscaler.ziacloud.zia_cloud_app_control_rules_info:
    provider: '{{ provider }}'
    name: "Webmail Rule-1"
    rule_type: "WEBMAIL"
"""

RETURN = r"""
rules:
    description: A list of cloud application control rules that match the specified criteria.
    returned: always
    type: list
    elements: dict
    sample: [
        {
            "access_control": "READ_WRITE",
            "actions": [
                "ALLOW_WEBMAIL_VIEW",
                "ALLOW_WEBMAIL_ATTACHMENT_SEND"
            ],
            "applications": [
                "GOOGLE_WEBMAIL",
                "YAHOO_WEBMAIL",
                "WINDOWS_LIVE_HOTMAIL"
            ],
            "browser_eun_template_id": 0,
            "cascading_enabled": false,
            "enforce_time_validity": false,
            "eun_enabled": false,
            "eun_template_id": 0,
            "id": 552617,
            "name": "Webmail Rule-1",
            "order": 2,
            "predefined": false,
            "rank": 7,
            "state": "DISABLED",
            "type": "WEBMAIL"
        }
    ]
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)

def normalize_settings(data):
    """Remove keys with None values and normalize unordered lists for comparison."""
    if isinstance(data, dict):
        return {
            k: normalize_settings(v)
            for k, v in data.items()
            if v is not None
        }
    elif isinstance(data, list):
        try:
            return sorted([normalize_settings(v) for v in data if v is not None])
        except Exception:
            return [normalize_settings(v) for v in data if v is not None]
    return data

def core(module):
    state = module.params.get("state")
    if state != "present":
        module.fail_json(msg="Only 'present' is supported for this module.")

    client = ZIAClientHelper(module)

    # Define all valid fields supported in the EUN payload
    params = [
        "enable_dynamic_content_cat", "consider_embedded_sites", "enforce_safe_search",
        "enable_office365", "enable_msft_o365", "enable_ucaas_zoom", "enable_ucaas_log_me_in",
        "enable_ucaas_ring_central", "enable_ucaas_webex", "enable_ucaas_talkdesk",
        "enable_chat_gpt_prompt", "enable_microsoft_copilot_prompt", "enable_gemini_prompt",
        "enable_poe_prompt", "enable_meta_prompt", "enable_perplexity_prompt", "block_skype",
        "enable_newly_registered_domains", "enable_block_override_for_non_auth_user",
        "enable_cipa_compliance"
    ]

    settings_data = {
        k: module.params.get(k)
        for k in params
        if module.params.get(k) is not None
           and not (isinstance(module.params.get(k), str) and module.params.get(k).strip() == "")
    }

    # 1) Fetch current EUN settings from the SDK
    current_settings, _, error = client.url_filtering.get_url_and_app_settings()
    if error:
        module.fail_json(msg=f"Error fetching url and app settings: {to_native(error)}")

    # 2) Convert both current/desired data to normalized dicts
    current_dict = normalize_settings(current_settings.as_dict())
    desired_dict = normalize_settings(settings_data)

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
        module.warn(f"🧼 Cleaned payload sent to SDK: {desired_dict}")
        updated, _, error = client.url_filtering.update_url_and_app_settings(**desired_dict)
        if error:
            module.fail_json(msg=f"Error url and app settings: {to_native(error)}")

        module.exit_json(changed=True, end_user_notifications=updated.as_dict())
    else:
        module.exit_json(changed=False, msg="No drift detected; nothing to update.")


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            enable_dynamic_content_cat=dict(type="bool", required=False),
            consider_embedded_sites=dict(type="bool", required=False),
            enforce_safe_search=dict(type="bool", required=False),
            enable_office365=dict(type="bool", required=False),
            enable_msft_o365=dict(type="bool", required=False),
            enable_ucaas_zoom=dict(type="bool", required=False),
            enable_ucaas_log_me_in=dict(type="bool", required=False),
            enable_ucaas_ring_central=dict(type="bool", required=False),
            enable_ucaas_webex=dict(type="bool", required=False),
            enable_ucaas_talkdesk=dict(type="bool", required=False),
            enable_chat_gpt_prompt=dict(type="bool", required=False),
            enable_microsoft_copilot_prompt=dict(type="bool", required=False),
            enable_gemini_prompt=dict(type="bool", required=False),
            enable_poe_prompt=dict(type="bool", required=False),
            enable_meta_prompt=dict(type="bool", required=False),
            enable_perplexity_prompt=dict(type="bool", required=False),
            block_skype=dict(type="bool", required=False),
            enable_newly_registered_domains=dict(type="bool", required=False),
            enable_block_override_for_non_auth_user=dict(type="bool", required=False),
            enable_cipa_compliance=dict(type="bool", required=False),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
