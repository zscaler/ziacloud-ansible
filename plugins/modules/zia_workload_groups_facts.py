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
module: zia_workload_groups_facts
short_description: "Get a list of workload groups."
description:
  - "Get a list of workload groups."
author:
  - William Guilherme (@willguibr)
version_added: "0.1.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider

options:
  id:
    description: "A unique identifier assigned to the workload group"
    required: false
    type: int
  name:
    type: str
    required: false
    description:
      - The name of the workload group
"""

EXAMPLES = r"""
- name: Gets list of all workload groups
  zscaler.ziacloud.zia_workload_groups_facts:
    provider: '{{ provider }}'

- name: Gets a workload group by name
  zscaler.ziacloud.zia_workload_groups_facts:
    provider: '{{ provider }}'
    name: "Example"

- name: Gets a workload group by ID
  zscaler.ziacloud.zia_workload_groups_facts:
    provider: '{{ provider }}'
    name: "12345676"
"""

RETURN = r"""
# Returns information about Workload groups.
"""

import json
from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def serialize_complex_data(group):
    if "expression_json" in group:
        group["expression_json"] = json.dumps(group["expression_json"])
    if "last_modified_by" in group:
        group["last_modified_by"] = json.dumps(group["last_modified_by"])
    return group


def core(module):
    group_id = module.params.get("id", None)
    group_name = module.params.get("name", None)
    client = ZIAClientHelper(module)

    # Initialize the result
    result = dict(changed=False)

    try:
        # Case 1: Return all groups if no name or ID is provided
        if group_id is None and group_name is None:
            groups = client.workload_groups.list_groups()
            if groups is None:
                module.fail_json(msg="No workload groups found")
            else:
                result["workload_groups"] = [
                    serialize_complex_data(group) for group in groups
                ]

        # Case 2: Return group by name
        elif group_name is not None:
            group = client.workload_groups.get_group_by_name(group_name)
            if group is None:
                module.fail_json(
                    msg=f"No workload group found with name '{group_name}'"
                )
            else:
                result["workload_group"] = group

        # Case 3: Return group by ID
        elif group_id is not None:
            group = client.workload_groups.get_group_by_id(group_id)
            if group is None:
                module.fail_json(msg=f"No workload group found with id '{group_id}'")
            else:
                result["workload_group"] = group

        # Serialize complex data structures for Ansible compatibility
        if "workload_group" in result:
            if "expression_json" in result["workload_group"]:
                result["workload_group"]["expression_json"] = json.dumps(
                    result["workload_group"]["expression_json"]
                )

            if "last_modified_by" in result["workload_group"]:
                result["workload_group"]["last_modified_by"] = json.dumps(
                    result["workload_group"]["last_modified_by"]
                )

    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())

    module.exit_json(**result)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
