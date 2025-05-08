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
module: zia_rule_labels_info
short_description: "Gets a list of rule labels"
description:
  - "Gets a list of rule labels"
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
    description: "The unique identifier for the rule label."
    type: int
    required: false
  name:
    description: "The rule label name."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets all list of rule label
  zscaler.ziacloud.zia_rule_labels_info:
    provider: '{{ provider }}'

- name: Gets a list of rule label by name
  zscaler.ziacloud.zia_rule_labels_info:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
labels:
  description: A list of rule labels fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the rule label.
      returned: always
      type: int
      sample: 3687131
    name:
      description: The name of the rule label.
      returned: always
      type: str
      sample: "Example"
    description:
      description: A description of the rule label.
      returned: always
      type: str
      sample: "Example description"
    created_by:
      description: Information about the user who created the rule label.
      returned: always
      type: complex
      contains:
        id:
          description: The identifier of the user who created the rule label.
          returned: always
          type: int
          sample: 44772836
        name:
          description: The name of the user who created the rule label.
          returned: always
          type: str
          sample: "admin@44772833.zscalertwo.net"
    last_modified_by:
      description: Information about the user who last modified the rule label.
      returned: always
      type: complex
      contains:
        id:
          description: The identifier of the user who last modified the rule label.
          returned: always
          type: int
          sample: 44772836
        name:
          description: The name of the user who last modified the rule label.
          returned: always
          type: str
          sample: "admin@44772833.zscalertwo.net"
    last_modified_time:
      description: The Unix timestamp when the rule label was last modified.
      returned: always
      type: int
      sample: 1721347034
    referenced_rule_count:
      description: The number of rules that reference this label.
      returned: always
      type: int
      sample: 0
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    label_id = module.params.get("id")
    label_name = module.params.get("name")

    client = ZIAClientHelper(module)
    labels = []

    if label_id is not None:
        label_obj, _unused, error = client.rule_labels.get_label(label_id)
        if error or label_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve Rule Label with ID '{label_id}': {to_native(error)}"
            )
        labels = [label_obj.as_dict()]
    else:
        query_params = {}
        if label_name:
            query_params["search"] = label_name

        result, _unused, error = client.rule_labels.list_labels(
            query_params=query_params
        )
        if error:
            module.fail_json(msg=f"Error retrieving Rule Labels: {to_native(error)}")

        label_list = [g.as_dict() for g in result] if result else []

        if label_name:
            matched = next((g for g in label_list if g.get("name") == label_name), None)
            if not matched:
                available = [g.get("name") for g in label_list]
                module.fail_json(
                    msg=f"Rule Label with name '{label_name}' not found. Available labels: {available}"
                )
            labels = [matched]
        else:
            labels = label_list

    module.exit_json(changed=False, labels=labels)


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
