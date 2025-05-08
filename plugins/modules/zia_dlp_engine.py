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
module: zia_dlp_engine
short_description: "Adds a new custom DLP engine."
description: "Adds a new custom DLP engine."
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
    description: "The unique identifier for the DLP engine."
    type: int
  name:
    description:
        - The DLP engine name as configured by the admin.
        - This attribute is required in POST and PUT requests for custom DLP engines.
    required: true
    type: str
  description:
    description: "The DLP engine description."
    required: false
    type: str
  engine_expression:
    description:
        - The logical expression that defines a DLP engine by combining DLP dictionaries using logical operators.
        - Namely All (AND), Any (OR), Exclude (NOT), and Sum (the total number of content matches).
        - ((D63.S > 1)).
        - ((D38.S > 1) AND (D63.S > 1)).
        - ((D38.S > 1) OR (D63.S > 1)).
        - (SUM(D63.S, D38.S) > 3).
        - In the preceding examples, 63 represents the ID of the Credit Cards dictionary ID.
        - 61 is the Financial Statements ID, and 38 is the ABA Bank Routing Numbers dictionary ID.
        - Each dictionary ID is wrapped around by a prefix (D) and a suffix (.S).
    type: str
    required: false
  custom_dlp_engine:
    description: "The DLP engine description."
    required: false
    type: bool
"""

EXAMPLES = r"""
- name: Create/Update/Delete custom dlp engine.
  zscaler.ziacloud.zia_dlp_engine:
    provider: '{{ provider }}'
    name: "Example"
    description: "Example"
    engine_expression: "((D63.S > 1))"
    custom_dlp_engine: true
"""

RETURN = r"""
# The newly created dlp engine resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import deleteNone
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_dlp_engine(engine):
    """Normalize dlp engine data by removing computed values"""
    normalized = engine.copy() if engine else {}
    computed_values = ["id"]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    params = ["id", "name", "description", "engine_expression", "custom_dlp_engine"]

    dlp_engine = {param: module.params.get(param) for param in params}
    engine_id = dlp_engine.get("id")
    engine_name = dlp_engine.get("name")

    existing_engine = None
    if engine_id:
        result = client.dlp_engine.get_dlp_engines(engine_id)
        if result[2]:  # Error check
            module.fail_json(
                msg=f"Error fetching DLP engine ID {engine_id}: {to_native(result[2])}"
            )
        existing_engine = (
            result[0].as_dict() if result[0] else None
        )  # Changed to_dict() to as_dict()
    else:
        result = client.dlp_engine.list_dlp_engines()
        if result[2]:  # Error check
            module.fail_json(msg=f"Error listing DLP engines: {to_native(result[2])}")
        for engine in result[0]:
            if engine.name == engine_name:
                existing_engine = engine.as_dict()  # Changed to_dict() to as_dict()
                break

    # Normalize and compare states
    desired = normalize_dlp_engine(dlp_engine)
    current = normalize_dlp_engine(existing_engine) if existing_engine else {}

    # Drift detection
    differences_detected = False
    for key, value in desired.items():
        if current.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current.get(key)}, Desired: {value}"
            )

    if module.check_mode:
        if state == "present" and (existing_engine is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_engine:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_engine:
            if differences_detected:
                update_data = deleteNone(
                    {
                        "engine_id": existing_engine["id"],
                        "name": dlp_engine.get("name"),
                        "description": dlp_engine.get("description"),
                        "engine_expression": dlp_engine.get("engine_expression"),
                        "custom_dlp_engine": dlp_engine.get("custom_dlp_engine"),
                    }
                )
                module.warn("Payload Update for SDK: {}".format(update_data))
                updated = client.dlp_engine.update_dlp_engine(**update_data)
                if updated[2]:
                    module.fail_json(
                        msg=f"Error updating DLP engine: {to_native(updated[2])}"
                    )
                module.exit_json(
                    changed=True, data=updated[0].as_dict()
                )  # Changed to_dict() to as_dict()
            else:
                module.exit_json(changed=False, data=existing_engine)
        else:
            create_data = deleteNone(
                {
                    "name": dlp_engine.get("name"),
                    "description": dlp_engine.get("description"),
                    "engine_expression": dlp_engine.get("engine_expression"),
                    "custom_dlp_engine": dlp_engine.get("custom_dlp_engine"),
                }
            )
            module.warn("Payload Update for SDK: {}".format(create_data))
            created = client.dlp_engine.add_dlp_engine(**create_data)
            if created[2]:
                module.fail_json(
                    msg=f"Error creating DLP engine: {to_native(created[2])}"
                )
            module.exit_json(
                changed=True, data=created[0].as_dict()
            )  # Changed to_dict() to as_dict()
    elif state == "absent":
        if existing_engine:
            deleted = client.dlp_engine.delete_dlp_engine(
                engine_id=existing_engine["id"]
            )
            if deleted[2]:
                module.fail_json(
                    msg=f"Error deleting DLP engine: {to_native(deleted[2])}"
                )
            module.exit_json(changed=True, data=existing_engine)
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        engine_expression=dict(type="str", required=False),
        custom_dlp_engine=dict(type="bool", required=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
