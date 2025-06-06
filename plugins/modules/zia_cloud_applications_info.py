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
module: zia_cloud_applications_info
short_description: "Retrieves a list of Predefined and User Defined Cloud Applications"
description:
  - Retrieves a list of Predefined and User Defined Cloud Applications associated with the DLP rules
  - Cloud App Control rules, Advanced Settings, Bandwidth Classes, and File Type Control rules
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
  mode:
    description:
      - Type of supported application to be filtered.
    type: str
    choices:
      - app_policy
      - ssl_policy
    required: true

  app_class:
    description:
      - Filter application by application category.
    type: str
    choices:
      - WEB_MAIL
      - SOCIAL_NETWORKING
      - STREAMING
      - P2P
      - INSTANT_MESSAGING
      - WEB_SEARCH
      - GENERAL_BROWSING
      - ADMINISTRATION
      - ENTERPRISE_COLLABORATION
      - BUSINESS_PRODUCTIVITY
      - SALES_AND_MARKETING
      - SYSTEM_AND_DEVELOPMENT
      - CONSUMER
      - FILE_SHARE
      - HOSTING_PROVIDER
      - IT_SERVICES
      - DNS_OVER_HTTPS
      - HUMAN_RESOURCES
      - LEGAL
      - HEALTH_CARE
      - FINANCE
      - CUSTOM_CAPP
      - AI_ML
    required: false

  app_name:
    description:
        - Cloud application name
    type: str
    required: false

  group_results:
    description:
        - Show count of applications grouped by application category
    type: bool
    required: false
"""

EXAMPLES = r"""
- name: Gets a list of all groups
  zscaler.ziacloud.zia_cloud_applications_info:
    provider: '{{ provider }}'
    mode: ssl_policy
    app_class: WEB_MAIL
    group_results: false
"""

RETURN = r"""
applications:
  description: Retrieves a list of Predefined and User Defined Cloud Applications
  returned: always
  type: list
  elements: dict
  contains:
    app:
      description: Application enum constant
      type: str
      sample: GOOGLE_WEBMAIL
    app_name:
      description: Cloud application name
      type: str
      sample: Gmail
    parent:
      description: Application category enum constant
      type: str
      sample: WEB_MAIL
    parent_name:
      description: Name of the cloud application category
      type: str
      sample: Web Mail
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    collect_all_items,
)


def core(module):
    client = ZIAClientHelper(module)

    mode = module.params.get("mode")
    if mode not in ["app_policy", "ssl_policy"]:
        module.fail_json(
            msg="Parameter 'mode' must be either 'app_policy' or 'ssl_policy'"
        )

    app_name = module.params.get("app_name")
    query_params = {}

    supported_params = ["app_class", "group_results"]
    for param in supported_params:
        val = module.params.get(param)
        if val is not None:
            query_params[param] = val

    if app_name:
        query_params["search"] = app_name  # Used by ZIA API

    list_fn = (
        client.cloud_applications.list_cloud_app_policy
        if mode == "app_policy"
        else client.cloud_applications.list_cloud_app_ssl_policy
    )

    try:
        results, err = collect_all_items(list_fn, query_params=query_params)
        if err:
            module.fail_json(msg=f"Error retrieving applications: {to_native(err)}")

        all_apps = [app.as_dict() if hasattr(app, "as_dict") else app for app in results]

        if app_name:
            matched = next((a for a in all_apps if a.get("app_name") == app_name), None)
            if not matched:
                available = [a.get("app_name") for a in all_apps]
                module.fail_json(
                    msg=f"Cloud application with name '{app_name}' not found. Available: {available}"
                )
            all_apps = [matched]

        module.exit_json(changed=False, applications=all_apps)

    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            mode=dict(type="str", choices=["app_policy", "ssl_policy"], required=True),
            app_name=dict(type="str", required=False),
            group_results=dict(type="bool", required=False),
            app_class=dict(
                type="str",
                required=False,
                choices=[
                    "WEB_MAIL",
                    "SOCIAL_NETWORKING",
                    "STREAMING",
                    "P2P",
                    "INSTANT_MESSAGING",
                    "WEB_SEARCH",
                    "GENERAL_BROWSING",
                    "ADMINISTRATION",
                    "ENTERPRISE_COLLABORATION",
                    "BUSINESS_PRODUCTIVITY",
                    "SALES_AND_MARKETING",
                    "SYSTEM_AND_DEVELOPMENT",
                    "CONSUMER",
                    "FILE_SHARE",
                    "HOSTING_PROVIDER",
                    "IT_SERVICES",
                    "DNS_OVER_HTTPS",
                    "HUMAN_RESOURCES",
                    "LEGAL",
                    "HEALTH_CARE",
                    "FINANCE",
                    "CUSTOM_CAPP",
                    "AI_ML",
                ],
            ),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
