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
module: zia_bandwidth_control_rules_info
short_description: "Retrieves all the rules in the Bandwidth Control policy."
description: "Retrieves all the rules in the Bandwidth Control policy."
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
    description: "Unique identifier for the Bandwidth Control Rule"
    type: int
    required: false
  name:
    description: "Name of the Bandwidth Control Rule"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all ZIA Bandwidth Control Rule
  zscaler.ziacloud.zia_bandwidth_control_rules_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a ZIA Bandwidth Control Rule by Name
  zscaler.ziacloud.zia_bandwidth_control_rules_info:
    provider: '{{ provider }}'
    name: "Example"
"""

RETURN = r"""
rules:
  description: A list of ZIA Bandwidth Control Rules.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier of the Bandwidth Control Rule.
      returned: always
      type: int
      sample: 1197791
    name:
      description: The name of the Bandwidth Control Rule.
      returned: always
      type: str
      sample: "DNAT_1"
    access_control:
      description: Access control setting for the rule, describing the access permission.
      returned: always
      type: str
      sample: "READ_WRITE"
    bandwidth_classes:
      description: The bandwidth classes to which you want to apply this rule
      returned: always
      type: list
      elements: int
      sample: [4, 8]
    order:
      description: The order of the rule in the list of Bandwidth Control Rule.
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
    protocols:
      description: List of protocols to which the rule applies.
      returned: always
      type: list
      sample: ["HTTPS_RULE", "HTTP_RULE"]
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
    rule_id = module.params.get("id")
    rule_name = module.params.get("name")

    client = ZIAClientHelper(module)
    rules = []

    if rule_id is not None:
        rules_obj, _unused, error = client.bandwidth_control_rules.get_rule(rule_id)
        if error or rules_obj is None:
            module.fail_json(msg=f"Failed to retrieve Bandwidth Control Rule with ID '{rule_id}': {to_native(error)}")
        rules = [rules_obj.as_dict()]
    else:
        result, _unused, error = client.bandwidth_control_rules.list_rules()
        if error:
            module.fail_json(msg=f"Error retrieving Bandwidth Control Rules: {to_native(error)}")

        rule_list = [i.as_dict() for i in result] if result else []

        if rule_name:
            matched = next((i for i in rule_list if i.get("name") == rule_name), None)
            if not matched:
                available = [i.get("name") for i in rule_list]
                module.fail_json(msg=f"Bandwidth Control Rule named '{rule_name}' not found. Available: {available}")
            rules = [matched]
        else:
            rules = rule_list

    module.exit_json(changed=False, rules=rules)


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
