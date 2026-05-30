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
module: zia_ips_signature_rules_info
short_description: "Gets a list of custom IPS Signature Rules"
description:
  - "Gets a list of custom IPS (Intrusion Prevention System) signature rules, or a single rule by ID or name."
author:
  - William Guilherme (@willguibr)
version_added: "2.1.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  id:
    description: "The unique identifier for the IPS Signature Rule."
    required: false
    type: int
  name:
    description: "The name of the IPS Signature Rule."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather information about all IPS Signature Rules
  zscaler.ziacloud.zia_ips_signature_rules_info:
    provider: '{{ provider }}'

- name: Gather information about an IPS Signature Rule by name
  zscaler.ziacloud.zia_ips_signature_rules_info:
    provider: '{{ provider }}'
    name: "Custom_IPS_Rule_Example"

- name: Gather information about an IPS Signature Rule by ID
  zscaler.ziacloud.zia_ips_signature_rules_info:
    provider: '{{ provider }}'
    id: 1254654
"""

RETURN = r"""
rules:
  description: A list of IPS Signature Rules matching the query.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the IPS Signature Rule.
      type: int
      sample: 1254654
    name:
      description: The name of the IPS Signature Rule.
      type: str
      sample: "Custom_IPS_Rule_Example"
    description:
      description: Additional notes about the IPS Signature Rule.
      type: str
    rule_text:
      description: The custom signature rule text.
      type: str
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
        rule_obj, _unused, error = client.ips_signature_rules.get_ips_signature_rule(rule_id)
        if error or rule_obj is None:
            module.fail_json(msg=f"Failed to retrieve IPS Signature Rule with ID '{rule_id}': {to_native(error)}")
        rules = [rule_obj.as_dict()]
    else:
        result, _unused, error = client.ips_signature_rules.list_ips_signature_rules()
        if error:
            module.fail_json(msg=f"Error retrieving IPS Signature Rules: {to_native(error)}")
        rule_list = [r.as_dict() for r in result] if result else []
        if rule_name:
            matched = next((r for r in rule_list if r.get("name") == rule_name), None)
            if not matched:
                available = [r.get("name") for r in rule_list]
                module.fail_json(msg=f"IPS Signature Rule with name '{rule_name}' not found. Available rules: {available}")
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
