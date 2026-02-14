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
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zia_traffic_capture_rules_info
short_description: "Gets information about Traffic Capture policy rules"
description:
  - "Gets Traffic Capture policy rules configured in the ZIA Admin Portal."
  - "Retrieves a specific rule by ID or name."
  - "If neither id nor name is provided, lists all rules."
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
    description:
      - The unique identifier for the Traffic Capture policy rule.
    required: false
    type: int
  name:
    description:
      - The name of the Traffic Capture policy rule.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all Traffic Capture policy rules
  zscaler.ziacloud.zia_traffic_capture_rules_info:
    provider: '{{ provider }}'

- name: Get a Traffic Capture rule by ID
  zscaler.ziacloud.zia_traffic_capture_rules_info:
    provider: '{{ provider }}'
    id: 1254654

- name: Get a Traffic Capture rule by name
  zscaler.ziacloud.zia_traffic_capture_rules_info:
    provider: '{{ provider }}'
    name: "Capture Rule 01"
"""

RETURN = r"""
rules:
  description: A list of Traffic Capture policy rules fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
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

    if rule_id is not None:
        result, _unused, error = client.traffic_capture.get_rule(rule_id)
        if error:
            module.fail_json(msg=f"Failed to retrieve Traffic Capture rule with ID '{rule_id}': {to_native(error)}")
        rules_out = [result.as_dict()]
    else:
        query_params = {"rule_name": rule_name} if rule_name else {}
        result, _unused, error = client.traffic_capture.list_rules(query_params=query_params if query_params else None)
        if error:
            module.fail_json(msg=f"Error retrieving Traffic Capture rules: {to_native(error)}")
        rules_list = [r.as_dict() for r in result] if result else []

        if rule_name:
            matched = next(
                (r for r in rules_list if r.get("name") == rule_name),
                None,
            )
            if matched is None:
                module.fail_json(msg=f"Traffic Capture rule with name '{rule_name}' not found.")
            rules_out = [matched]
        else:
            rules_out = rules_list

    module.exit_json(changed=False, rules=rules_out)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
