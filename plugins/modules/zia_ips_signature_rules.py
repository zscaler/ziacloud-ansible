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
module: zia_ips_signature_rules
short_description: "Manages ZIA custom IPS Signature Rules"
description:
  - "Adds, updates, or deletes a custom IPS (Intrusion Prevention System) signature rule."
  - "On create, the supplied C(rule_text) is validated against the ZIA dynamic-validation endpoint before submission."
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
  - zscaler.ziacloud.fragments.state

options:
  id:
    description: "The unique identifier for the IPS Signature Rule."
    required: false
    type: int
  name:
    description: "The name of the IPS Signature Rule."
    required: true
    type: str
  description:
    description: "Additional notes or information about the IPS Signature Rule."
    required: false
    type: str
  rule_text:
    description:
      - The custom signature rule text in Suricata/Snort-style syntax.
      - On create, this value is validated against the ZIA dynamic-validation endpoint before submission.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Create/Update an IPS Signature Rule
  zscaler.ziacloud.zia_ips_signature_rules:
    provider: '{{ provider }}'
    name: "Custom_IPS_Rule_Example"
    description: "Blocks requests to /admin"
    rule_text: >-
      alert http any any -> any any (msg:"HTTP /admin"; content:"/admin";
      http_uri; nocase; sid:1000010; rev:1;)
    state: present

- name: Delete an IPS Signature Rule by name
  zscaler.ziacloud.zia_ips_signature_rules:
    provider: '{{ provider }}'
    name: "Custom_IPS_Rule_Example"
    state: absent
"""

RETURN = r"""
data:
  description: The IPS Signature Rule resource record after the operation.
  returned: on success
  type: dict
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
      sample: "Blocks requests to /admin"
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

IPS_SIGNATURE_PARAMS = ["id", "name", "description", "rule_text"]


def normalize_rule(rule):
    """
    Remove computed attributes from an IPS signature rule dict so the desired
    and existing states can be compared cleanly.
    """
    normalized = rule.copy() if rule else {}
    computed_values = [
        "category",
        "enabled",
        "deleted",
        "promote_time",
        "rule_text_mod_time",
        "dynamic_validation_submitted",
        "dynamic_validation_rejected",
        "dynamic_validation_succeeded",
        "disabled_from_zscm",
        "dynamic_val_reject_code",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    rule_params = {p: module.params.get(p) for p in IPS_SIGNATURE_PARAMS}
    rule_id = rule_params.get("id")
    rule_name = rule_params.get("name")

    existing_rule = None
    if rule_id is not None:
        result, _unused, error = client.ips_signature_rules.get_ips_signature_rule(rule_id)
        if error:
            module.fail_json(msg=f"Error fetching IPS Signature Rule with id {rule_id}: {to_native(error)}")
        if result:
            existing_rule = result.as_dict()
    else:
        result, _unused, error = client.ips_signature_rules.list_ips_signature_rules()
        if error:
            module.fail_json(msg=f"Error listing IPS Signature Rules: {to_native(error)}")
        rules_list = [rule.as_dict() for rule in result] if result else []
        if rule_name:
            for rule in rules_list:
                if rule.get("name") == rule_name:
                    existing_rule = rule
                    break

    desired = normalize_rule({k: v for k, v in rule_params.items() if v is not None})
    current = normalize_rule(existing_rule) if existing_rule else {}

    differences_detected = False
    for key, value in desired.items():
        if key == "id":
            continue
        if current.get(key) != value:
            differences_detected = True
            module.warn(f"Difference detected in {key}. Current: {current.get(key)}, Desired: {value}")

    if module.check_mode:
        if state == "present" and (existing_rule is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_rule:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_rule:
            if differences_detected:
                rule_id_to_update = existing_rule.get("id")
                if not rule_id_to_update:
                    module.fail_json(msg="Cannot update IPS Signature Rule: ID is missing from the existing resource.")

                updated_rule, _unused, error = client.ips_signature_rules.update_ips_signature_rule(
                    rule_id=rule_id_to_update,
                    name=rule_params.get("name"),
                    description=rule_params.get("description"),
                    rule_text=rule_params.get("rule_text"),
                )
                if error:
                    module.fail_json(msg=f"Error updating IPS Signature Rule: {to_native(error)}")
                module.exit_json(changed=True, data=updated_rule.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule)
        else:
            new_rule, _unused, error = client.ips_signature_rules.add_ips_signature_rule(
                name=rule_params.get("name"),
                description=rule_params.get("description"),
                rule_text=rule_params.get("rule_text"),
            )
            if error:
                module.fail_json(msg=f"Error adding IPS Signature Rule: {to_native(error)}")
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            rule_id_to_delete = existing_rule.get("id")
            if not rule_id_to_delete:
                module.fail_json(msg="Cannot delete IPS Signature Rule: ID is missing from the existing resource.")

            _unused, _unused, error = client.ips_signature_rules.delete_ips_signature_rule(rule_id_to_delete)
            if error:
                module.fail_json(msg=f"Error deleting IPS Signature Rule: {to_native(error)}")
            module.exit_json(changed=True, data=existing_rule)
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
            rule_text=dict(type="str", required=False),
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
