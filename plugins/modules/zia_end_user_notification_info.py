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
module: zia_end_user_notification_info
short_description: Retrieves browser-based end user notification (EUN)
description: Retrieves browser-based end user notification (EUN) configuration details
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

options: {}
"""

EXAMPLES = r"""
- name: Retrieves browser-based end user notification
  zscaler.ziacloud.zia_end_user_notification_info:
    provider: '{{ provider }}'
"""

RETURN = r"""
notification:
  description: Browser-based End User Notification (EUN) configuration settings.
  returned: always
  type: dict
  contains:
    aup_day_offset:
      description: Specifies which day of the week or month the AUP is shown when aupFrequency is set. Valid range is 1 to 31.
      type: int
      sample: 0
    aup_frequency:
      description: The frequency at which the Acceptable Use Policy (AUP) is shown to end users.
      type: str
      sample: NEVER
    aup_message:
      description: The acceptable use statement that is shown in the AUP.
      type: str
      sample: ""
    caution_again_after:
      description: Time interval at which caution notification is shown for restricted sites.
      type: int
      sample: 300
    caution_custom_text:
      description: Custom message that appears in the caution notification.
      type: str
      sample: Proceeding to visit the site may violate your company policy.
    caution_per_domain:
      description: Whether the caution notification is shown per domain.
      type: bool
      sample: false
    custom_text:
      description: Custom text shown in the End User Notification.
      type: str
      sample: Website blocked
    display_comp_logo:
      description: Whether the organization's logo appears in the notification.
      type: bool
      sample: true
    display_comp_name:
      description: Whether the organization's name appears in the notification.
      type: bool
      sample: true
    display_reason:
      description: Whether the reason for blocking or cautioning is displayed in the notification.
      type: bool
      sample: true
    idp_proxy_notification_text:
      description: Message that appears in the IdP Proxy notification.
      type: str
      sample: ""
    notification_type:
      description: Type of End User Notification, either DEFAULT or CUSTOM.
      type: str
      sample: DEFAULT
    org_policy_link:
      description: Link to the organization's policy page.
      type: str
      sample: http://44772833.zscalertwo.net/policy.html
    quarantine_custom_notification_text:
      description: Message shown during file quarantine analysis.
      type: str
      sample: We are checking this file for a potential security risk. ...
    security_review_enabled:
      description: Whether the Security Violation notification is enabled.
      type: bool
      sample: false
    security_review_submit_to_security_cloud:
      description: Whether Security Violation review requests are submitted to Security Cloud.
      type: bool
      sample: false
    security_review_text:
      description: Message that appears for Security Violation notifications.
      type: str
      sample: Click to request security review.
    support_email:
      description: IT support email address displayed in the notification.
      type: str
      sample: support@44772833.zscalertwo.net
    support_phone:
      description: IT support phone number displayed in the notification.
      type: str
      sample: +91-9000000000
    url_cat_review_enabled:
      description: Whether the URL Categorization Review notification is enabled.
      type: bool
      sample: false
    url_cat_review_submit_to_security_cloud:
      description: Whether URL Categorization Review requests are submitted to Security Cloud.
      type: bool
      sample: false
    url_cat_review_text:
      description: Message that appears in the URL Categorization Review notification.
      type: str
      sample: If you believe you received this message in error, please click here to request a review of this site.
    web_dlp_review_enabled:
      description: Whether the Web DLP Violation notification is enabled.
      type: bool
      sample: false
    web_dlp_review_submit_to_security_cloud:
      description: Whether Web DLP Review requests are submitted to Security Cloud.
      type: bool
      sample: false
    web_dlp_review_text:
      description: Message that appears in the Web DLP Violation notification.
      type: str
      sample: Click to request policy review.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    client = ZIAClientHelper(module)

    eun, _unused, error = client.end_user_notification.get_eun_settings()
    if error:
        module.fail_json(msg=f"Error fetching advanced settings: {to_native(error)}")

    module.exit_json(changed=False, notification=eun.as_dict())


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
