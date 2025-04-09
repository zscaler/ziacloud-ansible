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
module: zia_url_filtering_rule_info
short_description: "Gets all url filtering rules."
description: "Gets all rules in the URL filtering policy."
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
    description: "URL Filtering Rule ID"
    required: false
    type: int
  name:
    description: "Name of the URL filtering rule"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all URL filtering rules
  zscaler.ziacloud.zia_url_filtering_rule_info:
    provider: '{{ provider }}'

- name: Gather Information Details of of a URL filtering rules
  zscaler.ziacloud.zia_url_filtering_rule_info:
    provider: '{{ provider }}'
    name: "Example"
"""

RETURN = r"""
rules:
  description: A list of URL filtering rules fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the URL filtering rule.
      returned: always
      type: int
      sample: 1203256
    name:
      description: The name of the URL filtering rule.
      returned: always
      type: str
      sample: "URL_Filtering_1"
    state:
      description: The current state of the URL filtering rule.
      returned: always
      type: str
      sample: "ENABLED"
    access_control:
      description: Access control setting for the rule.
      returned: always
      type: str
      sample: "READ_WRITE"
    action:
      description: Action taken when the rule is matched.
      returned: always
      type: str
      sample: "ALLOW"
    block_override:
      description: Indicates if the block action can be overridden.
      returned: always
      type: bool
      sample: false
    departments:
      description: List of departments to which the rule applies.
      returned: always
      type: list
      elements: dict
      contains:
        id:
          description: The unique identifier for the department.
          returned: always
          type: int
          sample: 99364434
        name:
          description: The name of the department.
          returned: always
          type: str
          sample: "A000"
    groups:
      description: List of groups to which the rule applies.
      returned: always
      type: list
      elements: dict
      contains:
        id:
          description: The unique identifier for the group.
          returned: always
          type: int
          sample: 76662385
        name:
          description: The name of the group.
          returned: always
          type: str
          sample: "A000"
    protocols:
      description: List of protocols to which the rule applies.
      returned: always
      type: list
      sample: ["HTTPS_RULE", "HTTP_RULE"]
    user_agent_types:
      description: User agent types affected by the rule.
      returned: always
      type: list
      sample: ["OPERA", "MSIE", "MSEDGE", "CHROME"]
    device_trust_levels:
      description: Device trust levels applicable to the rule.
      returned: always
      type: list
      sample: ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
    user_risk_score_levels:
      description: User risk score levels applicable to the rule.
      returned: always
      type: list
      sample: ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    order:
      description: The order of the rule within the ruleset.
      returned: always
      type: int
      sample: 1
    rank:
      description: The rank of the rule for execution priority.
      returned: always
      type: int
      sample: 7
    request_methods:
      description: HTTP request methods to which the rule applies.
      returned: always
      type: list
      sample: ["GET", "POST", "HEAD"]
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
        receivers_obj, _, error = client.url_filtering.get_rule(receiver_id)
        if error or receivers_obj is None:
            module.fail_json(msg=f"Failed to retrieve URL Filtering Rule with ID '{receiver_id}': {to_native(error)}")
        receivers = [receivers_obj.as_dict()]
    else:
        result, _, error = client.url_filtering.list_rules()
        if error:
            module.fail_json(msg=f"Error retrieving URL Filtering Rules: {to_native(error)}")

        receiver_list = [i.as_dict() for i in result] if result else []

        if receiver_name:
            matched = next((i for i in receiver_list if i.get("name") == receiver_name), None)
            if not matched:
                available = [i.get("name") for i in receiver_list]
                module.fail_json(msg=f"URL Filtering Rule named '{receiver_name}' not found. Available: {available}")
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
