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

def core(module):
    client = ZIAClientHelper(module)

    url_app_settings, _, error = client.url_filtering.get_url_and_app_settings()
    if error:
        module.fail_json(msg=f"Error fetching url and app settings: {to_native(error)}")

    module.exit_json(changed=False, settings=url_app_settings.as_dict())

def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())

if __name__ == "__main__":
    main()
