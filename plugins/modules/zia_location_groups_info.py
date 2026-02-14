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
module: zia_location_groups_info
short_description: "Gets locations only, not sub-locations."
description:
  - "Gets locations only, not sub-locations."
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
    description: "Unique identifier for the location group"
    type: int
    required: false
  name:
    description: The location group's name.
    required: false
    type: str
  group_type:
    description: The location group's type (i.e., Static or Dynamic).
    required: false
    type: str
    choices:
        - STATIC
        - DYNAMIC
  last_mod_user:
    description: The admin who modified the location group last.
    required: false
    type: str
  comments:
    description: Additional comments or information about the location group.
    required: false
    type: str
  location_id:
    description: The unique identifier for a location within a location group.
    required: false
    type: int
  version:
    description: The version parameter is for Zscaler internal use only. The version is used by the service for backup operations.
    required: false
    type: int
"""

EXAMPLES = r"""
- name: Gather Information Details of all ZIA Locations
  zscaler.ziacloud.zia_location_groups_info:
    provider: '{{ provider }}'

- name: Gather Information Details of ZIA Location Group By ID
  zscaler.ziacloud.zia_location_groups_info:
    provider: '{{ provider }}'
    name: "845875645"

- name: Gather Information Details of ZIA Location Group By Name
  zscaler.ziacloud.zia_location_groups_info:
    provider: '{{ provider }}'
    name: "USA-SJC37"

- name: Gather Information Details of ZIA Location Group Type
  zscaler.ziacloud.zia_location_groups_info:
    provider: '{{ provider }}'
    group_type: STATIC
"""

RETURN = r"""
locations:
  description: A list of location groups managed within the ZIA platform.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the location group.
      returned: always
      type: int
      sample: 64365143
    name:
      description: The name of the location group.
      returned: always
      type: str
      sample: "SDWAN_CAN"
    comments:
      description: Additional comments or information about the location group.
      returned: always
      type: str
      sample: "SDWAN_CAN"
    locations:
      description: The name of the location group.
      returned: always
      type: list
      elements: dict
      sample: "SDWAN_CAN"
    group_type:
      description: The location group's type (i.e., Static or Dynamic).
      returned: always
      type: str
      sample: "DYNAMIC_GROUP"
    last_mod_time:
      description: Automatically populated with the current time, after a successful POST or PUT request.
      returned: always
      type: str
      sample: 1676614490
    predefined:
      description: Predefined location group
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


def core(module):
    group_id = module.params.get("id")
    group_name = module.params.get("name")

    query_params = {}

    # Only include supported filtering attributes
    for param in ["group_type", "last_mod_user", "comments", "location_id", "version"]:
        val = module.params.get(param)
        if val is not None:
            query_params[param] = val

    client = ZIAClientHelper(module)
    locations = []

    if group_id is not None:
        location_obj, _unused, error = client.locations.get_location_group(group_id)
        if error or location_obj is None:
            module.fail_json(msg=f"Failed to retrieve location group with ID '{group_id}': {to_native(error)}")
        locations = [location_obj.as_dict()]
    else:
        # Implicit search support
        if group_name:
            query_params["search"] = group_name

        result, _unused, error = client.locations.list_location_groups(query_params=query_params)
        if error:
            module.fail_json(msg=f"Error retrieving location groups: {to_native(error)}")

        location_list = [l.as_dict() for l in result] if result else []

        if group_name:
            matched = next((l for l in location_list if l.get("name") == group_name), None)
            if not matched:
                available = [l.get("name") for l in location_list]
                module.fail_json(msg=f"Location group named '{group_name}' not found. Available: {available}")
            locations = [matched]
        else:
            locations = location_list

    module.exit_json(changed=False, locations=locations)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
        group_type=dict(type="str", required=False, choices=["STATIC", "DYNAMIC"]),
        last_mod_user=dict(type="str", required=False),
        comments=dict(type="str", required=False),
        location_id=dict(type="int", required=False),
        version=dict(type="int", required=False),
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
