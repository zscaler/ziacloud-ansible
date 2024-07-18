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
module: zia_cloud_firewall_filtering_rule_info
short_description: Retrieves rules in the Cloud Firewall module.
description: Retrieves rules in the Cloud Firewall module.
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
        - Unique identifier for the Firewall Filtering policy rule.
    type: int
    required: false
  name:
    description:
        - Name of the Firewall Filtering policy rule
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of a ZIA Cloud Firewall Rule
  zscaler.ziacloud.zia_cloud_firewall_filtering_rule_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a ZIA Cloud Firewall Rule by Name
  zscaler.ziacloud.zia_cloud_firewall_filtering_rule_info:
    provider: '{{ provider }}'
    name: "Example"
"""

RETURN = r"""
# Returns information on a specified ZIA Cloud Firewall Rule.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    rule_id = module.params.get("id", None)
    rule_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    rules = []

    if rule_id is not None:
        # Fetch rule by ID directly
        rule_box = client.firewall.get_rule(rule_id=rule_id)
        if rule_box is None:
            module.fail_json(msg=f"Failed to retrieve Firewall Rule ID: '{rule_id}'")
        rules = [rule_box]
    else:
        # Fetch all rules from the SDK directly
        all_rules = client.firewall.list_rules()

        if rule_name is not None:
            # Search for the specific rule by name directly
            for rule in all_rules:
                if rule.get("name") == rule_name:
                    rules = [rule]
                    break

            # Handle case where no rule with the given name is found
            if not rules:
                module.fail_json(
                    msg=f"Failed to retrieve Firewall Rule Name: '{rule_name}'"
                )
        else:
            # Return all rules directly
            rules = list(all_rules)

    module.exit_json(changed=False, rules=rules)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
