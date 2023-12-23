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
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.credentials_set
  - zscaler.ziacloud.fragments.state
options:
  id:
    description: "The unique identifier for the DLP engine."
    required: false
    type: str
  name:
    description:
        - The DLP engine name as configured by the admin.
        - This attribute is required in POST and PUT requests for custom DLP engines.
    required: true
    type: str
  description:
    description: "The DLP engine description."
    required: true
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
    required: true
  custom_dlp_engine:
    description: "The DLP engine description."
    required: true
    type: bool
"""

EXAMPLES = r"""
- name: Create/Update/Delete custom dlp engine.
  zscaler.ziacloud.zia_dlp_engine:
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
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_dlp_engine(engine):
    """
    Normalize dlp engine data by setting computed values.
    """
    normalized = engine.copy()

    computed_values = [
        "id",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    dlp_engine = dict()
    params = [
        "id",
        "name",
        "description",
        "predefined_engine_name",
        "engine_expression",
        "custom_dlp_engine",
    ]
    for param_name in params:
        dlp_engine[param_name] = module.params.get(param_name, None)
    engine_id = dlp_engine.get("id", None)
    engine_name = dlp_engine.get("name", None)

    existing_engine = None
    if engine_id is not None:
        existing_engine = client.dlp.get_dlp_engines(engine_id).to_dict()
    else:
        dlp_engines = client.dlp.list_dlp_engines().to_list()
        if engine_name is not None:
            for dlp in dlp_engines:
                if dlp.get("name", None) == engine_name:
                    existing_engine = dlp
                    break

    # Normalize and compare existing and desired data
    desired_engine = normalize_dlp_engine(dlp_engine)
    current_engine = normalize_dlp_engine(existing_engine) if existing_engine else {}

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in desired_engine.items():
        if key not in fields_to_exclude and current_engine.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_engine.get(key)}, Desired: {value}"
            )

    if existing_engine is not None:
        id = existing_engine.get("id")
        existing_engine.update(desired_engine)
        existing_engine["id"] = id

    if state == "present":
        if existing_engine:
            if differences_detected:
                """Update"""
                update_engine = deleteNone(
                    dict(
                        engine_id=existing_engine.get("id", ""),
                        name=existing_engine.get("name", ""),
                        description=existing_engine.get("description", ""),
                        predefined_engine_name=existing_engine.get(
                            "predefined_engine_name", ""
                        ),
                        engine_expression=existing_engine.get("engine_expression", ""),
                        custom_dlp_engine=existing_engine.get("custom_dlp_engine", ""),
                    )
                )
                updated_engine = client.dlp.update_dlp_engine(**update_engine).to_dict()
                module.exit_json(changed=True, data=updated_engine)
            else:
                """No changes needed"""
                module.exit_json(
                    changed=False, data=existing_engine, msg="No changes detected."
                )
        else:
            """Create"""
            create_engine = deleteNone(
                dict(
                    name=dlp_engine.get("name", ""),
                    description=dlp_engine.get("description", ""),
                    predefined_engine_name=dlp_engine.get("predefined_engine_name", ""),
                    engine_expression=dlp_engine.get("engine_expression", ""),
                    custom_dlp_engine=dlp_engine.get("custom_dlp_engine", ""),
                )
            )
            new_engine = client.dlp.add_dlp_engine(**create_engine).to_dict()
            module.exit_json(changed=True, data=new_engine)
    elif (
        state == "absent"
        and existing_engine is not None
        and existing_engine.get("id") is not None
    ):
        code = client.dlp.delete_dlp_engine(engine_id=existing_engine.get("id"))
        if code > 299:
            module.exit_json(changed=False, data=None)
        module.exit_json(changed=True, data=existing_engine)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        predefined_engine_name=dict(type="str", required=False),
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
