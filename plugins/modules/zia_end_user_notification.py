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
module: zia_end_user_notification
short_description: "Retrieves browser-based end user notification (EUN)"
description:
  - "Retrieves browser-based end user notification (EUN) configuration details"
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
  aup_day_offset:
    description:
      - Specifies which day of the week or month the AUP is shown for users when aupFrequency is set.
      - Valid range is 1 to 31.
    type: int
    required: false
  aup_frequency:
    description: The frequency at which the Acceptable Use Policy (AUP) is shown to the end users
    type: str
    required: false
    choices:
        - NEVER
        - SESSION
        - DAILY
        - WEEKLY
        - ONLOGIN
        - CUSTOM
        - ON_DATE
        - ON_WEEKDAY
  aup_custom_frequency:
    description: The custom frequency (in days) for showing the AUP to the end users. Valid range is 1 to 180.
    type: int
    required: false
  aup_message:
    description: The acceptable use statement that is shown in the AUP
    type: str
    required: false
  caution_again_after:
    description:
      - The time interval at which the caution notification is shown when users continue browsing a restricted site.
      - The recommended setting for complex websites, such as Social Networking sites, is at least 5 minutes.
    type: int
    required: false
  caution_custom_text:
    description: The custom message that appears in the caution notification
    type: str
    required: false
  caution_per_domain:
    description:
      - Specifies whether to display the caution notification at a specific time interval for URLs in the Miscellaneous or Unknown category.
      - This option is applicable when a user browses a URL or a sub-domain of a URL in the Miscellaneous or Unknown category.
    type: bool
    required: false
  custom_text:
    description: The custom text shown in the EUN
    type: str
    required: false
  display_comp_logo:
    description: Indicates whether your organization's logo appears in the EUN or not
    type: bool
    required: false
  display_comp_name:
    description: Indicates whether the organization's name appears in the EUN or not
    type: bool
    required: false
  display_reason:
    description:
      - Indicates whether or not the reason for cautioning or blocking access to a site
      - file, or application is shown when the respective notification is triggered
    type: bool
    required: false
  idp_proxy_notification_text:
    description: The message that appears in the IdP Proxy notification
    type: str
    required: false
  notification_type:
    description: The type of EUN as default or custom
    type: str
    required: false
    choices:
        - DEFAULT
        - CUSTOM
  org_policy_link:
    description: The URL of the organization's policy page. This field is required for the default notification type.
    type: str
    required: false
  quarantine_custom_notification_text:
    description: The message that appears in the quarantine notification
    type: str
    required: false
  security_review_enabled:
    description: Indicates whether the Security Violation notification is enabled or disabled
    type: bool
    required: false
  security_review_submit_to_security_cloud:
    description:
      - Indicates whether users' review requests for blocked URLs are submitted
      - To the Zscaler service i.e. Security Cloud or a custom location.
    type: bool
    required: false
  security_review_text:
    description: The message that appears in the Security Violation notification
    type: str
    required: false
  security_review_custom_location:
    description: A custom URL location where users' review requests for possible misclassified URLs are sent
    type: str
    required: false
  support_email:
    description: The email address for writing to IT Support
    type: str
    required: false
  support_phone:
    description: The phone number for contacting IT Support
    type: str
    required: false
  redirect_url:
    description: The redirect URL for the external site hosting the EUN specified when the custom notification type is selected
    type: str
    required: false
  url_cat_review_enabled:
    description: Indicates whether the URL Categorization notification is enabled or disabled
    type: bool
    required: false
  url_cat_review_submit_to_security_cloud:
    description:
      - Indicates whether users' review requests for possibly misclassified URLs are submitted
      - to the Zscaler service (i.e., Security Cloud) or a custom location.
      - A true value indicates that the request is sent to the Security cloud,
      - whereas a false value indicates that the request is sent to the specified custom location.
    type: bool
    required: false
  url_cat_review_custom_location:
    description: A custom URL location where users' review requests for blocked URLs are sent
    type: str
    required: false
  url_cat_review_text:
    description: The message that appears in the URL Categorization notification
    type: str
    required: false
  web_dlp_review_enabled:
    description: Indicates whether the Web DLP Violation notification is enabled or disabled
    type: bool
    required: false
  web_dlp_review_submit_to_security_cloud:
    description:
      - Indicates whether users' review requests for web DLP policy violation are submitted to the
      - Zscaler service (i.e., Security Cloud) or a custom location.
      - A true value indicates that the request is sent to the Security cloud,
      - whereas a false value indicates that the request is sent to the specified custom location.
    type: bool
    required: false
  web_dlp_review_custom_location:
    description: A custom URL location where users' review requests for the web DLP policy violation are sent
    type: str
    required: false
  web_dlp_review_text:
    description: The message that appears in the Web DLP Violation notification
    type: str
    required: false
"""

EXAMPLES = r"""
- name: Retrieves browser-based end user notification (EUN) configuration details
  zscaler.ziacloud.zia_end_user_notification:
    provider: '{{ provider }}'
    notification_type: "CUSTOM"
    aup_frequency: "NEVER"
    aup_day_offset: 0
    display_reason: false
    display_comp_name: false
    display_comp_logo: false
    url_cat_review_enabled: true
    url_cat_review_submit_to_security_cloud: true
    url_cat_review_text: "If you believe you received this message in error, click here."
    security_review_enabled: true
    security_review_submit_to_security_cloud: true
    security_review_text: "Click to request security review."
    web_dlp_review_enabled: true
    web_dlp_review_custom_location: "https://redirect.acme.com"
    web_dlp_review_text: "Click to request policy review."
    redirect_url: "https://redirect.acme.com"
    support_email: "support@000000.zscalerthree.net"
    support_phone: "+91-9000000000"
    org_policy_link: "http://000000.zscalerthree.net/policy.html"
    caution_again_after: 300
    caution_per_domain: true
    caution_custom_text: "This action may violate company policy."
    quarantine_custom_notification_text: "We are scanning this file for your safety. It may take up to 10 minutes."
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
        "aup_frequency",
        "aup_custom_frequency",
        "aup_day_offset",
        "aup_message",
        "notification_type",
        "display_reason",
        "display_comp_name",
        "display_comp_logo",
        "custom_text",
        "url_cat_review_enabled",
        "url_cat_review_submit_to_security_cloud",
        "url_cat_review_custom_location",
        "url_cat_review_text",
        "security_review_enabled",
        "security_review_submit_to_security_cloud",
        "security_review_custom_location",
        "security_review_text",
        "web_dlp_review_enabled",
        "web_dlp_review_submit_to_security_cloud",
        "web_dlp_review_custom_location",
        "web_dlp_review_text",
        "redirect_url",
        "support_email",
        "support_phone",
        "org_policy_link",
        "caution_again_after",
        "caution_per_domain",
        "caution_custom_text",
        "idp_proxy_notification_text",
        "quarantine_custom_notification_text",
    ]

    settings_data = {
        k: module.params.get(k)
        for k in params
        if module.params.get(k) is not None and not (isinstance(module.params.get(k), str) and module.params.get(k).strip() == "")
    }

    # 1) Fetch current EUN settings from the SDK
    current_settings, _unused, error = client.end_user_notification.get_eun_settings()
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

        updated, _unused, error = client.end_user_notification.update_eun_settings(current_settings)
        if error:
            module.fail_json(msg=f"Error updating end user notification settings: {to_native(error)}")

        module.exit_json(changed=True, end_user_notifications=updated.as_dict())
    else:
        module.exit_json(changed=False, msg="No drift detected; nothing to update.")


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            aup_frequency=dict(
                type="str",
                required=False,
                choices=[
                    "NEVER",
                    "SESSION",
                    "DAILY",
                    "WEEKLY",
                    "ONLOGIN",
                    "CUSTOM",
                    "ON_DATE",
                    "ON_WEEKDAY",
                ],
            ),
            aup_custom_frequency=dict(type="int", required=False),
            aup_day_offset=dict(type="int", required=False),
            aup_message=dict(type="str", required=False),
            notification_type=dict(type="str", required=False, choices=["DEFAULT", "CUSTOM"]),
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
