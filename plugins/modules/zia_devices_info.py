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
module: zia_cloud_firewall_ip_destination_groups_info
short_description: "Gets a list of all IP destination groups"
description:
  - "Gets a list of all IP destination groups"
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
    description: "Unique identifer for the destination IP group"
    required: false
    type: int
  name:
    description: "Destination IP group name"
    required: false
    type: str
  exclude_type:
    description: Filter based on the IP destination group's type.
    required: false
    type: str
    choices:
      - DSTN_IP
      - DSTN_FQDN
      - DSTN_DOMAIN
      - DSTN_OTHER
"""

EXAMPLES = r"""
- name: Gather Information of all Destination Group
  zscaler.ziacloud.zia_cloud_firewall_ip_destination_groups_info:
    provider: '{{ provider }}'

- name: Gather Information of a Destination Group by Name
  zscaler.ziacloud.zia_cloud_firewall_ip_destination_groups_info:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
groups:
  description: List of IP destination groups based on the search criteria provided.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the IP destination group.
      returned: always
      type: int
      sample: 3254355
    name:
      description: The name of the IP destination group.
      returned: always
      type: str
      sample: "Sample_IP_Destination_Group"
    description:
      description: A description of the IP destination group.
      returned: always
      type: str
      sample: "Sample_IP_Destination_Group"
    creator_context:
      description: The context or origin within ZIA where this group was created.
      returned: always
      type: str
      sample: "ZIA"
    addresses:
      description: List of IP addresses included in the destination group.
      returned: always
      type: list
      sample: ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    ip_categories:
      description: List of IP categories associated with the destination group.
      returned: always
      type: list
      sample: []
    type:
      description: Type of the destination group.
      returned: always
      type: str
      sample: "DSTN_IP"
    url_categories:
      description: List of URL categories associated with the destination group.
      returned: always
      type: list
      sample: []
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import collect_all_items


def core(module):
    device_name = module.params.get("name")
    model = module.params.get("model")
    owner = module.params.get("owner")
    os_type = module.params.get("os_type")
    os_version = module.params.get("os_version")
    device_group_id = module.params.get("device_group_id")
    user_ids = module.params.get("user_ids")
    search_all = module.params.get("search_all")
    include_all = module.params.get("include_all")

    client = ZIAClientHelper(module)

    query_params = {}
    if model is not None:
        query_params["model"] = model
    if owner is not None:
        query_params["owner"] = owner
    if os_type is not None:
        query_params["osType"] = os_type
    if os_version is not None:
        query_params["osVersion"] = os_version
    if device_group_id is not None:
        query_params["deviceGroupId"] = device_group_id
    if user_ids is not None:
        query_params["userIds"] = ",".join(map(str, user_ids))
    if include_all is not None:
        query_params["includeAll"] = include_all
    if search_all is not None:
        query_params["searchAll"] = search_all
    if device_name:
        query_params["deviceName"] = device_name

    results, err = collect_all_items(client.device_management.list_devices, query_params=query_params)
    if err:
        module.fail_json(msg=f"Error retrieving devices: {to_native(err)}")

    device_list = [d.as_dict() if hasattr(d, "as_dict") else d for d in results] if results else []

    if device_name:
        matched = next((d for d in device_list if d.get("name") == device_name), None)
        if not matched:
            available = [d.get("name") for d in device_list]
            module.fail_json(msg=f"Device with name '{device_name}' not found. Available devices: {available}")
        device_list = [matched]

    module.exit_json(changed=False, devices=device_list)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        model=dict(type="str", required=False),
        owner=dict(type="str", required=False),
        os_type=dict(type="str", required=False),
        os_version=dict(type="str", required=False),
        device_group_id=dict(type="int", required=False),
        user_ids=dict(type="list", elements="int", required=False),
        search_all=dict(type="str", required=False),
        include_all=dict(type="bool", required=False),
    )

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
