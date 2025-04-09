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
module: zia_forwarding_control_rule_info
short_description: "Gets all rules in the Forwarding Control policy."
description: "Gets the list of forwarding rules configured in the ZIA Admin Portal."
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
    description: "Unique identifier for the Forwarding Filtering policy rule"
    type: int
    required: false
  name:
    description: "Name of the Forwarding Filtering policy rule"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all ZIA Forwarding Control Rule
  zscaler.ziacloud.zia_forwarding_control_rule_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a ZIA Forwarding Control Rule by Name
  zscaler.ziacloud.zia_forwarding_control_rule_info:
    provider: '{{ provider }}'
    name: "Example"
"""

RETURN = r"""
rules:
  description: A list of ZIA forwarding control rules.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier of the forwarding rule.
      returned: always
      type: int
      sample: 1197791
    name:
      description: The name of the forwarding control rule.
      returned: always
      type: str
      sample: "FWD_1"
    access_control:
      description: Access control setting for the rule, describing the access permission.
      returned: always
      type: str
      sample: "READ_WRITE"
    dest_addresses:
      description: List of destination IP addresses for the rule.
      returned: always
      type: list
      elements: str
      sample: ["192.168.100.1", "192.168.100.2", "192.168.100.3"]
    dest_countries:
      description: List of destination country codes affected by the rule.
      returned: always
      type: list
      elements: str
      sample: ["COUNTRY_CA", "COUNTRY_GB"]
    dest_ip_categories:
      description: List of destination IP categories specified in the rule.
      returned: always
      type: list
      elements: str
    dest_ip_groups:
      description: List of destination IP groups affected by the rule.
      returned: always
      type: list
      elements: dict
      contains:
        id:
          description: The unique identifier of the IP group.
          returned: always
          type: int
          sample: 3254355
        name:
          description: The name of the IP group.
          returned: always
          type: str
          sample: "Example1000"
    forward_method:
      description: The forwarding method specified in the rule (e.g., DIRECT, VPN).
      returned: always
      type: str
      sample: "DIRECT"
    order:
      description: The order of the rule in the list of forwarding rules.
      returned: always
      type: int
      sample: 1
    rank:
      description: The rank assigned to the rule for priority.
      returned: always
      type: int
      sample: 7
    state:
      description: The state of the rule (e.g., ENABLED, DISABLED).
      returned: always
      type: str
      sample: "ENABLED"
    type:
      description: The type of forwarding rule.
      returned: always
      type: str
      sample: "FORWARDING"
    location_groups:
      description: List of location groups associated with the rule.
      returned: always
      type: list
      elements: dict
      contains:
        id:
          description: The unique identifier of the location group.
          returned: always
          type: int
          sample: 44772849
        name:
          description: The name of the location group.
          returned: always
          type: str
          sample: "Server Traffic Group"
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    receiver_id = module.params.get("id")
    receiver_name = module.params.get("name")

    client = ZIAClientHelper(module)
    receivers = []

    if receiver_id is not None:
        receivers_obj, _, error = client.forwarding_control.get_rule(receiver_id)
        if error or receivers_obj is None:
            module.fail_json(msg=f"Failed to retrieve Forwarding Control Rule with ID '{receiver_id}': {to_native(error)}")
        receivers = [receivers_obj.as_dict()]
    else:
        result, _, error = client.forwarding_control.list_rules()
        if error:
            module.fail_json(msg=f"Error retrieving Forwarding Control Rules: {to_native(error)}")

        receiver_list = [i.as_dict() for i in result] if result else []

        if receiver_name:
            matched = next((i for i in receiver_list if i.get("name") == receiver_name), None)
            if not matched:
                available = [i.get("name") for i in receiver_list]
                module.fail_json(msg=f"Forwarding Control Rule named '{receiver_name}' not found. Available: {available}")
            receivers = [matched]
        else:
            receivers = receiver_list

    module.exit_json(changed=False, receivers=receivers)


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
