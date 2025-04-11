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
module: zia_user_management_groups_info
short_description: "Gets a list of user groups. "
description:
  - "Gets a list of user groups. "
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
    description: "Group ID."
    required: false
    type: int
  name:
    description: "Group name."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets a list of all groups
  zscaler.ziacloud.zia_user_management_groups_info:
    provider: '{{ provider }}'

- name: Gets a list of a single group
  zscaler.ziacloud.zia_user_management_groups_info:
    provider: '{{ provider }}'
    name: "marketing"
"""

RETURN = r"""
groups:
  description: List of groups retrieved by the module.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the group.
      type: int
      sample: 76662385
    name:
      description: The name of the group.
      type: str
      sample: 'A000'
  sample: [
    {
      "id": 76662385,
      "name": "A000"
    }
  ]
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper

def core(module):
    client = ZIAClientHelper(module)

    mode = module.params.get("mode")
    if mode not in ["app_policy", "ssl_policy"]:
        module.fail_json(msg="Parameter 'mode' must be either 'app_policy' or 'ssl_policy'")

    query_params = {}
    name = module.params.get("name")

    supported_params = ["app_class", "group_results"]
    for param in supported_params:
        val = module.params.get(param)
        if val is not None:
            query_params[param] = val

    query_params.setdefault("page_size", 200)

    # Choose SDK function
    list_fn = client.cloud_applications.list_cloud_app_policy if mode == "app_policy" else client.cloud_applications.list_cloud_app_ssl_policy

    try:
        items = []

        # ✅ Fetch first page
        result, response, error = list_fn(query_params)
        if error:
            module.fail_json(msg=f"Error fetching page 1 for {mode}: {to_native(error)}")

        items.extend(result or [])

        if name:
            for item in items:
                if item.name == name:
                    module.exit_json(changed=False, applications=[item.as_dict() if hasattr(item, "as_dict") else item])

        # ✅ Paginate and check for match if name is provided
        while response and response.has_next():
            page, error = response.next()
            if error:
                module.fail_json(msg=f"Pagination error in {mode}: {to_native(error)}")
            if not page:
                break
            for item in page:
                if name and item.name == name:
                    module.exit_json(changed=False, applications=[item.as_dict()])
                items.append(item)

        # Final return
        module.exit_json(changed=False, applications=[i.as_dict() if hasattr(i, "as_dict") else i for i in items])

    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())

def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(dict(
        mode=dict(type="str", choices=["app_policy", "ssl_policy"], required=True),
        app_class=dict(type="str", required=False),
        group_results=dict(type="bool", required=False),
    ))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())

if __name__ == "__main__":
    main()
