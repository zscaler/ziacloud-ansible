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
module: zia_cloud_firewall_network_application_info
short_description: "Gets a list of all network application groups."
description:
  - "Gets a list of all network application groups."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
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
        - The unique identifier for the network application
    required: false
    type: str
  name:
    description:
        - The search string used to match against a network application's description attribute."
    required: false
    type: str
  locale:
    description:
        - When set to one of the supported locales (i.e., en-US, de-DE, es-ES, fr-FR, ja-JP, zh-CN).
        - The network application's description is localized into the requested language.
        - Provide a BCP 47 language tag. Visit the following site for reference U(https://www.techonthenet.com/js/language_tags.php)
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all Network Applicactions
  zscaler.ziacloud.zia_cloud_firewall_network_application_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a Network Applicaction
  zscaler.ziacloud.zia_cloud_firewall_network_application_info:
    provider: '{{ provider }}'
    name: "APNS"
"""

RETURN = r"""
network_apps:
  description: List of network applications based on the search criteria provided.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the network application.
      returned: always
      type: str
      sample: "APNS"
    description:
      description: A description of the network application.
      returned: always
      type: str
      sample: "APNS_DESC"
    parent_category:
      description: The parent category to which the network application belongs.
      returned: always
      type: str
      sample: "APP_SERVICE"
    deprecated:
      description: Indicates whether the network application is deprecated.
      returned: always
      type: bool
      sample: false
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    validate_locale_code,
)


def core(module):
    app_id = module.params.get("id")
    app_name = module.params.get("name")
    locale = module.params.get("locale")
    if locale and not validate_locale_code(locale):
        module.fail_json(
            msg=(
                f"Invalid locale '{locale}'. Must be a valid BCP 47 language tag (e.g., en-US, fr-FR, ja-JP). "
                "See: https://www.techonthenet.com/js/language_tags.php"
            )
        )

    client = ZIAClientHelper(module)
    apps = []

    if app_id:
        app_obj, _unused, error = client.cloud_firewall.get_network_app(app_id)
        if error or app_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve Network Application with ID '{app_id}': {to_native(error)}"
            )
        apps = [app_obj.as_dict()]
    else:
        query_params = {}
        if app_name:
            query_params["search"] = app_name
        if locale:
            query_params["locale"] = locale

        result, _unused, error = client.cloud_firewall.list_network_apps(
            query_params=query_params
        )
        if error:
            module.fail_json(
                msg=f"Error retrieving Network Applications: {to_native(error)}"
            )

        app_list = [a.as_dict() for a in result] if result else []

        if app_name:
            matched = next((a for a in app_list if a.get("id") == app_name), None)
            if not matched:
                available = [a.get("id") for a in app_list]
                module.fail_json(
                    msg=f"Network Application with ID '{app_name}' not found. Available: {available}"
                )
            apps = [matched]
        else:
            apps = app_list

    module.exit_json(changed=False, apps=apps)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="str", required=False),
        locale=dict(
            type="str",
            required=False,
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["name", "id"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
