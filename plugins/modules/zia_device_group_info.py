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
module: zia_device_group_info
short_description: "Gets a list of device groups"
description:
  - "Gets a list of device groups."
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
  id:
    description: The unique identifer for the device group.
    required: false
    type: int
  name:
    description: The device group name.
    required: false
    type: str
  include_device_info:
    description: Include or exclude device information.
    required: false
    type: bool
  include_pseudo_groups:
    description: Include or exclude Zscaler Client Connector and Cloud Browser Isolation-related device groups.
    required: false
    type: bool
"""

EXAMPLES = r"""
- name: Gather Information of all Device Group
  zscaler.ziacloud.zia_device_group_info:
    provider: '{{ provider }}'

- name: Gather Information of a Device Group by ID
  zscaler.ziacloud.zia_device_group_info:
    provider: '{{ provider }}'
    id: 1234598

- name: Gather Information of a Device Group by Name
  zscaler.ziacloud.zia_device_group_info:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
groups:
  description: List of device groups.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifer for the device group.
      returned: always
      type: int
      sample: 3254355
    name:
      description: The device group name.
      returned: always
      type: str
      sample: "Windows"
    os_type:
      description: The operating system (OS).
      returned: always
      type: str
      sample: "Windows"
    group_type:
      description: The device group type.
      returned: always
      type: str
      sample: "ZCC_OS"
    predefined:
      description: Indicates whether this is a predefined device group. If this value is set to true, the group is predefined.
      returned: always
      type: str
      sample: true
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    group_name = module.params.get("name")
    include_device_info = module.params.get("include_device_info")
    include_pseudo_groups = module.params.get("include_pseudo_groups")

    client = ZIAClientHelper(module)

    query_params = {}
    if include_device_info is not None:
        query_params["include_device_info"] = include_device_info
    if include_pseudo_groups is not None:
        query_params["include_pseudo_groups"] = include_pseudo_groups

    groups, _unused, error = client.device_management.list_device_groups(
        query_params=query_params
    )
    if error:
        module.fail_json(msg=f"Error retrieving device groups: {to_native(error)}")

    all_groups = [g.as_dict() for g in groups]

    if group_name:
        matched = next((g for g in all_groups if g.get("name") == group_name), None)
        if not matched:
            available = [g.get("name") for g in all_groups]
            module.fail_json(
                msg=f"Group with name '{group_name}' not found. Available groups: {available}"
            )
        all_groups = [matched]

    module.exit_json(changed=False, groups=all_groups)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
        include_device_info=dict(type="bool", required=False),
        include_pseudo_groups=dict(type="bool", required=False),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
