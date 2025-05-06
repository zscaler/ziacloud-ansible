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
module: zia_url_filtering_and_cloud_app_settings
short_description: Gets the URL Filtering and Cloud App Control settings.
description: Gets the URL Filtering and Cloud App Control settings.
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI at https://pypi.org/project/zscaler-sdk-python/
notes:
  - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.modified_state

options:
  enable_dynamic_content_cat:
    description: Indicates if dynamic categorization of URLs by analyzing content of uncategorized websites using AI/ML tools is enabled or not.
    type: bool
    required: false
  consider_embedded_sites:
    description: Indicates if URL filtering rules must be applied to sites that are translated using translation services or not.
    type: bool
    required: false
  enforce_safe_search:
    description:
        - Indicates whether only safe content must be returned for web, image, and video search.
        - Safe search is supported for specific search engines and other platforms
    type: bool
    required: false
  enable_office365:
    description:
        - Enables or disables Microsoft Office 365 configuration.
        - If you want to continue using existing granular controls for Office 365
        - Recommended to turn off the enableMsftO365 option and enable this option instead.
        - This is a legacy option used for backward compatibility.
    type: bool
    required: false

  enable_msft_o365:
    description:
        - Indicates if the Zscaler service is allowed to permit secure local breakout for Office 365
        - Traffic automatically without any manual configuration needed.
        - Enabling this option turns off SSL Interception for all Office 365 destinations as per Microsoft's recommendation.
        - If you want to continue using existing granular controls for Office 365, disable this option and enable preexisting configuration.
    type: bool
    required: false

  enable_ucaas_zoom:
    description:
        - Indicates if the Zscaler service is allowed to automatically permit secure local breakout for Zoom traffic
        - Without any manual configuration needed. When enabled, this option turns off SSL interception for all Zoom destinations.
        - To continue using existing granular controls for Zoom traffic
        - Disable this option and enable Cloud Application and Firewall Network Application policies accordingly.
    type: bool
    required: false

  enable_ucaas_log_me_in:
    description:
        - Indicates if the Zscaler service is allowed to automatically permit secure local breakout for GoTo traffic
        - Without any manual configuration needed. When enabled, this option turns off SSL interception for all GoTo destinations.
        - To continue using existing granular controls for GoTo traffic
        - Disable this option and enable Cloud Application and Firewall Network Application policies accordingly.
    type: bool
    required: false

  enable_ucaas_ring_central:
    description:
        - Indicates if the Zscaler service is allowed to automatically permit secure local breakout for RingCentral traffic
        - Without any manual configuration needed. When enabled, this option turns off SSL interception for all RingCentral destinations
        - To continue using existing granular controls for RingCentral traffic
        - Disable this option and enable Cloud Application and Firewall Network Application policies accordingly.
    type: bool
    required: false

  enable_ucaas_webex:
    description:
        - Indicates if the Zscaler service is allowed to automatically permit secure local breakout for Webex traffic
        - Without any manual configuration needed. When enabled, this option turns off SSL interception for all Webex destinations
        - To continue using existing granular controls for Webex traffic
        - Disable this option and enable Cloud Application and Firewall Network Application policies accordingly.
    type: bool
    required: false

  enable_ucaas_talkdesk:
    description:
        - Indicates if the Zscaler service is allowed to automatically permit secure local breakout for Talkdesk traffic
        - With minimal or no manual configuration needed. When enabled, this option turns off SSL interception for all Talkdesk destinations
        - To continue using existing granular controls for Talkdesk traffic
        - Disable this option and enable Cloud Application, DNS, and Firewall Network Application policies accordingly.
    type: bool
    required: false

  enable_chat_gpt_prompt:
    description: Indicates if the use of generative AI prompts with ChatGPT by users should be categorized and logged
    type: bool
    required: false

  enable_microsoft_copilot_prompt:
    description: Indicates if the use of generative AI prompts with Microsoft Copilot by users should be categorized and logged
    type: bool
    required: false

  enable_gemini_prompt:
    description: Indicates if the use of generative AI prompts with Google Gemini by users should be categorized and logged
    type: bool
    required: false

  enable_poe_prompt:
    description: Indicates if the use of generative AI prompts with Poe by users should be categorized and logged
    type: bool
    required: false

  enable_meta_prompt:
    description: Indicates if the use of generative AI prompts with Meta AI by users should be categorized and logged
    type: bool
    required: false

  enable_perplexity_prompt:
    description: Indicates if the use of generative AI prompts with Perplexity by users should be categorized and logged
    type: bool
    required: false

  block_skype:
    description: Indicates whether access to Skype is blocked or not.
    type: bool
    required: false

  enable_newly_registered_domains:
    description: Indicates whether newly registered and observed domains that are identified within hours of going live are allowed or blocked
    type: bool
    required: false

  enable_block_override_for_non_auth_user:
    description: Indicates if authorized users can temporarily override block action on websites by providing their authentication information
    type: bool
    required: false

  enable_cipa_compliance:
    description: Indicates if the predefined CIPA Compliance Rule is enabled or not.
    type: bool
    required: false
"""

EXAMPLES = r"""
- name: Configure Advanced Url Filter And Cloud App Settings
  zscaler.ziacloud.zia_url_filtering_and_cloud_app_settings:
    provider: '{{ provider }}'
    block_skype: true
    consider_embedded_sites: true
    enable_block_override_for_non_auth_user: true
    enable_chat_gpt_prompt: false
    enable_cipa_compliance: false
    enable_dynamic_content_cat: true
    enable_gemini_prompt: false
    enable_meta_prompt: false
    enable_microsoft_co_pilot_prompt: false
    enable_msft_o365: true
    enable_newly_registered_domains: true
    enable_office365: true
    enable_per_plexity_prompt: false
    enable_poe_prompt: false
    enable_ucaas_log_me_in: false
    enable_ucaas_ring_central: false
    enable_ucaas_talkdesk: false
    enable_ucaas_webex: false
    enable_ucaas_zoom: true
    enforce_safe_search: true
"""

RETURN = r"""
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_settings(data):
    """Remove keys with None values and normalize unordered lists for comparison."""
    if isinstance(data, dict):
        return {k: normalize_settings(v) for k, v in data.items() if v is not None}
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
        "enable_dynamic_content_cat",
        "consider_embedded_sites",
        "enforce_safe_search",
        "enable_office365",
        "enable_msft_o365",
        "enable_ucaas_zoom",
        "enable_ucaas_log_me_in",
        "enable_ucaas_ring_central",
        "enable_ucaas_webex",
        "enable_ucaas_talkdesk",
        "enable_chat_gpt_prompt",
        "enable_microsoft_copilot_prompt",
        "enable_gemini_prompt",
        "enable_poe_prompt",
        "enable_meta_prompt",
        "enable_perplexity_prompt",
        "block_skype",
        "enable_newly_registered_domains",
        "enable_block_override_for_non_auth_user",
        "enable_cipa_compliance",
    ]

    settings_data = {
        k: module.params.get(k)
        for k in params
        if module.params.get(k) is not None
        and not (
            isinstance(module.params.get(k), str) and module.params.get(k).strip() == ""
        )
    }

    # 1) Fetch current EUN settings from the SDK
    current_settings, _unused, error = client.url_filtering.get_url_and_app_settings()
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
            module.warn(
                f"  {k}: current={current_dict.get(k)}, desired={desired_dict.get(k)}"
            )

    # 4) Respect check_mode
    if module.check_mode:
        module.exit_json(changed=drift)

    # 5) If drift, update the resource
    if drift:
        module.warn(f"🧼 Cleaned payload sent to SDK: {desired_dict}")
        updated, _unused, error = client.url_filtering.update_url_and_app_settings(
            **desired_dict
        )
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
