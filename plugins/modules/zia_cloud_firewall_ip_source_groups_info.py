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
module: zia_cloud_firewall_ip_source_groups_info
short_description: "Cloud Firewall IP source groups"
description:
  - "List of Cloud Firewall IP source groups"
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
    description: "A unique identifier of the source IP address group"
    type: int
    required: false
  name:
    description: "The name of the source IP address group"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all ip source groups
  zscaler.ziacloud.zia_cloud_firewall_ip_source_groups_info:
    provider: '{{ provider }}'

- name: Gather Information of an ip source group by name
  zscaler.ziacloud.zia_cloud_firewall_ip_source_groups_info:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
groups:
  description: List of IP source groups based on the search criteria provided.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the IP source group.
      returned: always
      type: int
      sample: 3266272
    name:
      description: The name of the IP source group.
      returned: always
      type: str
      sample: "Sample_IP_Source_Group"
    description:
      description: A description of the IP source group.
      returned: always
      type: str
      sample: "Sample_IP_Source_Group"
    creator_context:
      description: The context or origin within ZIA where this group was created.
      returned: always
      type: str
      sample: "ZIA"
    ip_addresses:
      description: List of IP addresses included in the source group.
      returned: always
      type: list
      sample: ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    is_non_editable:
      description: Whether the IP source group is editable or not.
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

    client = ZIAClientHelper(module)
    groups = []

    if group_id is not None:
        group_obj, _unused, error = client.cloud_firewall.get_ip_source_group(group_id)
        if error or group_obj is None:
            module.fail_json(msg=f"Failed to retrieve IP Source Group with ID '{group_id}': {to_native(error)}")
        groups = [group_obj.as_dict()]
    else:
        query_params = {}
        if group_name:
            query_params["search"] = group_name

        result, _unused, error = client.cloud_firewall.list_ip_source_groups(query_params=query_params)
        if error:
            module.fail_json(msg=f"Error retrieving IP Source Groups: {to_native(error)}")

        group_list = [g.as_dict() for g in result] if result else []

        if group_name:
            matched = next((g for g in group_list if g.get("name") == group_name), None)
            if not matched:
                available = [g.get("name") for g in group_list]
                module.fail_json(msg=f"IP Source Group with name '{group_name}' not found. Available groups: {available}")
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
        supports_check_mode=True,
        mutually_exclusive=[["name", "id"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
