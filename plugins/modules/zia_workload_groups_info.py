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
module: zia_workload_groups_info
short_description: "Get a list of workload groups."
description:
  - "Get a list of workload groups."
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
  zscaler.ziacloud.zia_workload_groups_info:
    provider: '{{ provider }}'

- name: Gets a workload group by name
  zscaler.ziacloud.zia_workload_groups_info:
    provider: '{{ provider }}'
    name: "Example"

- name: Gets a workload group by ID
  zscaler.ziacloud.zia_workload_groups_info:
    provider: '{{ provider }}'
    name: "12345676"
"""

RETURN = r"""
workload_group:
  description: Details of the workload group fetched.
  returned: when a specific group is requested
  type: dict
  contains:
    id:
      description: The unique identifier for the workload group.
      type: int
      sample: 17811899
    name:
      description: The name of the workload group.
      type: str
      sample: "BD_WORKLOAD_GROUP01"
    description:
      description: A brief description of the workload group.
      type: str
      sample: "BD_WORKLOAD_GROUP01"
    expression:
      description: Raw expression used in the workload group settings, typically complex and encoded.
      type: str
      sample: "Encoded expression string"
    expression_json:
      description: JSON format of the expression for more readable output, detailing the attributes and conditions used.
      type: str
      sample: >
        {
          "expression_containers": [
            {"tag_type": "ATTR", "operator": "AND", "tag_container": {"tags": [{"key": "GroupName", "value": "example"}], "operator": "AND"}},
            ...
          ]
        }
    last_modified_by:
      description: Information about the user who last modified the group.
      type: dict
      sample: {"id": 8061243, "name": "Admin User"}
    last_modified_time:
      description: UNIX timestamp of when the group was last modified.
      type: int
      sample: 1705956482
workload_groups:
  description: List of all workload groups retrieved if no specific group is requested.
  returned: when listing all groups and no specific group is requested
  type: list
  elements: dict
  sample: [
    {
      "id": 17811899,
      "name": "BD_WORKLOAD_GROUP01",
      "description": "BD_WORKLOAD_GROUP01",
      "expression": "Encoded expression string",
      "expression_json": "{...}",
      "last_modified_by": {"id": 8061243, "name": "Admin User"},
      "last_modified_time": 1705956482
    }
  ]
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
    group_id = module.params.get("id")
    group_name = module.params.get("name")

    client = ZIAClientHelper(module)

    # Fetch all workload groups
    result, _unused, error = client.workload_groups.list_groups()
    if error:
        module.fail_json(msg=f"Failed to retrieve workload groups: {to_native(error)}")

    all_groups = [g.as_dict() for g in result] if result else []

    matched = None
    if group_id is not None:
        matched = next(
            (g for g in all_groups if str(g.get("id")) == str(group_id)), None
        )
        if not matched:
            module.fail_json(msg=f"No workload group found with ID '{group_id}'")
    elif group_name is not None:
        matched = next((g for g in all_groups if g.get("name") == group_name), None)
        if not matched:
            module.fail_json(msg=f"No workload group found with name '{group_name}'")

    if matched:
        module.exit_json(changed=False, workload_group=serialize_complex_data(matched))
    else:
        serialized_groups = [serialize_complex_data(g) for g in all_groups]
        module.exit_json(changed=False, workload_groups=serialized_groups)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["id", "name"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
