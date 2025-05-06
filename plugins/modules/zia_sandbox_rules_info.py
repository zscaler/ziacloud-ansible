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
module: zia_sandbox_rules_info
short_description: "Retrieves the list of all Sandbox policy rules"
description: "Retrieves the list of all Sandbox policy rules configured in the ZIA Admin Portal"
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
    description: "Unique identifier for the Sandbox rule"
    type: int
    required: false
  name:
    description: "Name of the Sandboxy rule"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all ZIA Sandbox Rule
  zscaler.ziacloud.zia_sandbox_rules_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a ZIA Sandbox Rule by Name
  zscaler.ziacloud.zia_sandbox_rules_info:
    provider: '{{ provider }}'
    name: "Example"
"""

RETURN = r"""
rules:
  description: List of Sandbox policy rules retrieved.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Unique identifier for the Sandbox Rule.
      type: int
      sample: 552595
    name:
      description: Name of the Sandbox Rule.
      type: str
      sample: Default BA Rule
    description:
      description: Additional information about the rule.
      type: str
      sample: Default Rule Created during the company creation
    enabled:
      description: Determines whether the Sandbox Rule is enabled or disabled.
      type: bool
      sample: true
    order:
      description: Rule order number of the Sandbox Rule.
      type: int
      sample: 127
    rank:
      description: Admin rank of the Sandbox Rule.
      type: int
      sample: 7
    ml_action_enabled:
      description: Whether AI Instant Verdict (ML) is enabled for the Sandbox rule.
      type: bool
      sample: false
    first_time_enable:
      description: Indicates whether a first-time action is configured for the rule.
      type: bool
      sample: true
    first_time_operation:
      description: Action that must take place when users download unknown files for the first time.
      type: str
      sample: ALLOW_SCAN
    ba_rule_action:
      description: The action configured for the rule when traffic matches.
      type: str
      sample: BLOCK
    protocols:
      description: Protocols to which the rule applies.
      type: list
      elements: str
      sample:
        - ANY_RULE
    ba_policy_categories:
      description: Threat categories associated with the rule.
      type: list
      elements: str
      sample:
        - ADWARE_BLOCK
        - BOTMAL_BLOCK
    file_types:
      description: File types to which the Sandbox rule applies.
      type: list
      elements: str
      sample:
        - FTCATEGORY_WINDOWS_EXECUTABLES
        - FTCATEGORY_ZIP
    url_categories:
      description: URL categories associated with the rule.
      type: list
      elements: str
      sample:
        - NUDITY
        - PORNOGRAPHY
    locations:
      description: List of location IDs the rule applies to.
      type: list
      elements: dict
      contains:
        id:
          description: Identifier of the location.
          type: int
          sample: 256001376
    location_groups:
      description: List of location group IDs the rule applies to.
      type: list
      elements: dict
      contains:
        id:
          description: Identifier of the location group.
          type: int
          sample: 44772848
    departments:
      description: List of department IDs the rule applies to.
      type: list
      elements: dict
      contains:
        id:
          description: Identifier of the department.
          type: int
          sample: 99364442
    groups:
      description: List of group IDs the rule applies to.
      type: list
      elements: dict
      contains:
        id:
          description: Identifier of the group.
          type: int
          sample: 76662385
    users:
      description: List of user IDs the rule applies to.
      type: list
      elements: dict
      contains:
        id:
          description: Identifier of the user.
          type: int
          sample: 45513075
    labels:
      description: List of label IDs associated with the rule.
      type: list
      elements: dict
      contains:
        id:
          description: Identifier of the label.
          type: int
          sample: 4204140
    zpa_app_segments:
      description: List of ZPA Application Segments associated with the rule.
      type: list
      elements: dict
      contains:
        external_id:
          description: Indicates the external ID of the ZPA Application Segment.
          type: str
          sample: "2"
        name:
          description: The name of the ZPA Application Segment.
          type: str
          sample: Inspect App Segments
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
        rules_obj, _unused, error = client.sandbox_rules.get_rule(rule_id)
        if error or rules_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve Sandbox Rule with ID '{rule_id}': {to_native(error)}"
            )
        rules = [rules_obj.as_dict()]
    else:
        result, _unused, error = client.sandbox_rules.list_rules()
        if error:
            module.fail_json(
                msg=f"Error retrieving Sandbox Rule Rules: {to_native(error)}"
            )

        rule_list = [i.as_dict() for i in result] if result else []

        if rule_name:
            matched = next((i for i in rule_list if i.get("name") == rule_name), None)
            if not matched:
                available = [i.get("name") for i in rule_list]
                module.fail_json(
                    msg=f"Sandbox Rule named '{rule_name}' not found. Available: {available}"
                )
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
