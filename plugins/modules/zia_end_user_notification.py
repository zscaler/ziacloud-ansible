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
module: zia_atp_malware_policy
short_description: "Retrieves the malicious URLs added to the denylist"
description:
  - "Retrieves the malicious URLs added to the denylist in the (ATP) policy"
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

options:
  id:
    description: "The unique identifier for the rule label."
    type: int
    required: false
  name:
    description: "The rule label name."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets all list of rule label
  zscaler.ziacloud.zia_rule_labels_info:
    provider: '{{ provider }}'

- name: Gets a list of rule label by name
  zscaler.ziacloud.zia_rule_labels_info:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
labels:
  description: A list of rule labels fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the rule label.
      returned: always
      type: int
      sample: 3687131
    name:
      description: The name of the rule label.
      returned: always
      type: str
      sample: "Example"
    description:
      description: A description of the rule label.
      returned: always
      type: str
      sample: "Example description"
    created_by:
      description: Information about the user who created the rule label.
      returned: always
      type: complex
      contains:
        id:
          description: The identifier of the user who created the rule label.
          returned: always
          type: int
          sample: 44772836
        name:
          description: The name of the user who created the rule label.
          returned: always
          type: str
          sample: "admin@44772833.zscalertwo.net"
    last_modified_by:
      description: Information about the user who last modified the rule label.
      returned: always
      type: complex
      contains:
        id:
          description: The identifier of the user who last modified the rule label.
          returned: always
          type: int
          sample: 44772836
        name:
          description: The name of the user who last modified the rule label.
          returned: always
          type: str
          sample: "admin@44772833.zscalertwo.net"
    last_modified_time:
      description: The Unix timestamp when the rule label was last modified.
      returned: always
      type: int
      sample: 1721347034
    referenced_rule_count:
      description: The number of rules that reference this label.
      returned: always
      type: int
      sample: 0
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)

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
        "aup_frequency", "aup_custom_frequency", "aup_day_offset", "aup_message",
        "notification_type", "display_reason", "display_comp_name", "display_comp_logo",
        "custom_text", "url_cat_review_enabled", "url_cat_review_submit_to_security_cloud",
        "url_cat_review_custom_location", "url_cat_review_text", "security_review_enabled",
        "security_review_submit_to_security_cloud", "security_review_custom_location",
        "security_review_text", "web_dlp_review_enabled", "web_dlp_review_submit_to_security_cloud",
        "web_dlp_review_custom_location", "web_dlp_review_text", "redirect_url", "support_email",
        "support_phone", "org_policy_link", "caution_again_after", "caution_per_domain", "caution_custom_text",
        "idp_proxy_notification_text", "quarantine_custom_notification_text"
    ]

    settings_data = {
        k: module.params.get(k)
        for k in params
        if module.params.get(k) is not None
           and not (isinstance(module.params.get(k), str) and module.params.get(k).strip() == "")
    }

    # 1) Fetch current EUN settings from the SDK
    current_settings, _, error = client.end_user_notification.get_eun_settings()
    if error:
        module.fail_json(msg=f"Error fetching end user notification settings: {to_native(error)}")

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

        updated, _, error = client.end_user_notification.update_eun_settings(current_settings)
        if error:
            module.fail_json(msg=f"Error updating end user notification settings: {to_native(error)}")

        module.exit_json(changed=True, end_user_notifications=updated.as_dict())
    else:
        module.exit_json(changed=False, msg="No drift detected; nothing to update.")


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(dict(
        aup_frequency=dict(type="str", required=False),
        aup_custom_frequency=dict(type="int", required=False),
        aup_day_offset=dict(type="int", required=False),
        aup_message=dict(type="str", required=False),
        notification_type=dict(type="str", required=False),
        display_reason=dict(type="bool", required=False),
        display_comp_name=dict(type="bool", required=False),
        display_comp_logo=dict(type="bool", required=False),
        custom_text=dict(type="str", required=False),
        url_cat_review_enabled=dict(type="bool", required=False),
        url_cat_review_submit_to_security_cloud=dict(type="bool", required=False),
        url_cat_review_custom_location=dict(type="str", required=False),
        url_cat_review_text=dict(type="str", required=False),
        security_review_enabled=dict(type="bool", required=False),
        security_review_submit_to_security_cloud=dict(type="bool", required=False),
        security_review_custom_location=dict(type="str", required=False),
        security_review_text=dict(type="str", required=False),
        web_dlp_review_enabled=dict(type="bool", required=False),
        web_dlp_review_submit_to_security_cloud=dict(type="bool", required=False),
        web_dlp_review_custom_location=dict(type="str", required=False),
        web_dlp_review_text=dict(type="str", required=False),
        redirect_url=dict(type="str", required=False),
        support_email=dict(type="str", required=False),
        support_phone=dict(type="str", required=False),
        org_policy_link=dict(type="str", required=False),
        caution_again_after=dict(type="int", required=False),
        caution_per_domain=dict(type="bool", required=False),
        caution_custom_text=dict(type="str", required=False),
        idp_proxy_notification_text=dict(type="str", required=False),
        quarantine_custom_notification_text=dict(type="str", required=False),
        state=dict(type="str", choices=["present"], default="present")
    ))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
