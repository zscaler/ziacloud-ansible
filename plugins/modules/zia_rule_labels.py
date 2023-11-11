#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Technology Alliances, <zscaler-partner-labs@z-bd.com>

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

DOCUMENTATION = """
---
module: zia_rule_labels
short_description: "Adds a rule label."
description:
  - "Adds a rule label."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
    - zscaler.ziacloud.fragments.credentials_set
    - zscaler.ziacloud.fragments.provider
    - zscaler.ziacloud.fragments.enabled_state
options:
  id:
    description: ""
    required: false
    type: int
  name:
    description: "The rule label name."
    required: true
    type: str
  description:
    description:
      - The rule label description.
    required: false
    type: str
"""

EXAMPLES = """

- name: Create/Update/Delete rule label.
  zscaler.ziacloud.zia_rule_labels:
    name: "Example"
    description: "Example"
"""

RETURN = """
# The newly created rule label resource record.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_labels(group):
    """
    Normalize ip source group data by setting computed values.
    """
    normalized = group.copy()

    computed_values = [
        "id",
        "name",
        "description",
        "last_modified_time",
        "last_modified_by",
        "last_modified_by.id",
        "last_modified_by.name",
        "created_by",
        "created_by.id",
        "created_by.name",
        "referenced_rule_count",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    rule_label = dict()
    params = [
        "id",
        "name",
        "description",
    ]
    for param_name in params:
        rule_label[param_name] = module.params.get(param_name, None)
    label_id = rule_label.get("id", None)
    label_name = rule_label.get("name", None)

    existing_rule_label = None
    if label_id is not None:
        existing_rule_label = client.labels.get_label(label_id).to_dict()
    else:
        rule_labels = client.labels.list_labels().to_list()
        if label_name is not None:
            for label in rule_labels:
                if label.get("name", None) == label_name:
                    existing_rule_label = label
                    break

    # Normalize and compare existing and desired data
    normalized_label = normalize_labels(rule_label)
    normalized_existing_label = (
        normalize_labels(existing_rule_label) if existing_rule_label else {}
    )

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in normalized_label.items():
        if key not in fields_to_exclude and normalized_existing_label.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing_label.get(key)}, Desired: {value}"
            )

    if existing_rule_label is not None:
        id = existing_rule_label.get("id")
        existing_rule_label.update(normalized_label)
        existing_rule_label["id"] = id  # Ensure the ID is not overwritten by the update

    if state == "present":
        if existing_rule_label is not None:
            if differences_detected:
                """Update"""
                existing_rule_label = client.labels.update_label(
                    label_id=existing_rule_label.get("id", ""),
                    name=existing_rule_label.get("name", ""),
                    description=existing_rule_label.get("description", ""),
                ).to_dict()
                module.exit_json(changed=True, data=existing_rule_label)
        else:
            """Create"""
            rule_label = client.labels.add_label(
                name=rule_label.get("name", ""),
                description=rule_label.get("description", ""),
            ).to_dict()
            module.exit_json(changed=False, data=rule_label)
    elif state == "absent":
        if existing_rule_label is not None:
            code = client.labels.delete_label(existing_rule_label.get("id"))
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_rule_label)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
