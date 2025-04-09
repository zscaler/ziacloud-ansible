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
module: zia_rule_labels
short_description: "Adds a rule label."
description:
  - "Adds a rule label."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description: "The unique identifier for the rule label."
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

EXAMPLES = r"""

- name: Create/Update/Delete rule label.
  zscaler.ziacloud.zia_rule_labels:
    provider: '{{ provider }}'
    name: "Example"
    description: "Example"
"""

RETURN = r"""
# The newly created rule label resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper


def normalize_labels(label):
    """
    Remove computed attributes from a label dict to make comparison easier.
    """
    normalized = label.copy() if label else {}
    computed_values = [
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
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    rule_label_params = {p: module.params.get(p) for p in ["id", "name", "description"]}
    label_id = rule_label_params.get("id")
    label_name = rule_label_params.get("name")

    existing_rule_label = None

    if label_id:
        result, _, error = client.rule_labels.get_label(label_id)
        if error:
            module.fail_json(msg=f"Error fetching label with id {label_id}: {to_native(error)}")
        existing_rule_label = result.as_dict()
    else:
        result, _, error = client.rule_labels.list_labels()
        if error:
            module.fail_json(msg=f"Error listing labels: {to_native(error)}")
        labels_list = [label.as_dict() for label in result]
        if label_name:
            for label in labels_list:
                if label.get("name") == label_name:
                    existing_rule_label = label
                    break

    normalized_desired = normalize_labels(rule_label_params)
    normalized_existing = normalize_labels(existing_rule_label) if existing_rule_label else {}

    differences_detected = False
    for key, value in normalized_desired.items():
        if normalized_existing.get(key) != value:
            differences_detected = True
            module.warn(f"Difference detected in {key}. Current: {normalized_existing.get(key)}, Desired: {value}")

    if module.check_mode:
        if state == "present" and (existing_rule_label is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_rule_label:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_rule_label:
            if differences_detected:
                label_id_to_update = existing_rule_label.get("id")
                if not label_id_to_update:
                    module.fail_json(msg="Cannot update label: ID is missing from the existing resource.")

                updated_label, _, error = client.rule_labels.update_label(
                    label_id=label_id_to_update,
                    name=rule_label_params.get("name"),
                    description=rule_label_params.get("description")
                )
                if error:
                    module.fail_json(msg=f"Error updating label: {to_native(error)}")
                module.exit_json(changed=True, data=updated_label.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule_label)
        else:
            new_label, _, error = client.rule_labels.add_label(
                name=rule_label_params.get("name"),
                description=rule_label_params.get("description")
            )
            if error:
                module.fail_json(msg=f"Error adding label: {to_native(error)}")
            module.exit_json(changed=True, data=new_label.as_dict())

    elif state == "absent":
        if existing_rule_label:
            label_id_to_delete = existing_rule_label.get("id")
            if not label_id_to_delete:
                module.fail_json(msg="Cannot delete label: ID is missing from the existing resource.")

            _, _, error = client.rule_labels.delete_label(label_id_to_delete)
            if error:
                module.fail_json(msg=f"Error deleting label: {to_native(error)}")
            module.exit_json(changed=True, data=existing_rule_label)
        else:
            module.exit_json(changed=False, data={})

    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            id=dict(type="int", required=False),
            name=dict(type="str", required=True),
            description=dict(type="str", required=False),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
