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
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    collect_all_items
)


def core(module):
    group_id = module.params.get("id")
    group_name = module.params.get("name")

    client = ZIAClientHelper(module)
    groups = []

    if group_id is not None:
        result, _, error = client.user_management.get_group(group_id)
        if error or result is None:
            module.fail_json(msg=f"Failed to retrieve Group with ID '{group_id}': {to_native(error)}")
        groups = [result.as_dict()]
    else:
        query_params = {}
        if group_name:
            query_params["search"] = group_name

        result, err = collect_all_items(client.user_management.list_groups, query_params)
        if err:
            module.fail_json(msg=f"Error retrieving Groups: {to_native(err)}")

        group_list = [g.as_dict() if hasattr(g, "as_dict") else g for g in result] if result else []

        if group_name:
            matched = next((g for g in group_list if g.get("name") == group_name), None)
            if not matched:
                available = [g.get("name") for g in group_list]
                module.fail_json(msg=f"Group with name '{group_name}' not found. Available groups: {available}")
            groups = [matched]
        else:
            groups = group_list

    module.exit_json(changed=False, groups=groups)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        mutually_exclusive=[["name", "id"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
