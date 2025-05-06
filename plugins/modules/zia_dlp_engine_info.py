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
module: zia_dlp_engine_info
short_description: "Get a list of DLP engines."
description:
  - "Get a list of DLP engines."
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
    description: "The unique identifier for the DLP engine."
    type: int
    required: false
  name:
    type: str
    required: false
    description:
      - The DLP engine name as configured by the admin.
"""

EXAMPLES = r"""
- name: Gets all list of DLP Engines
  zscaler.ziacloud.zia_dlp_engine_info:
    provider: '{{ provider }}'

- name: Gets a list of DLP Engines by name
  zscaler.ziacloud.zia_dlp_engine_info:
    provider: '{{ provider }}'
    name: "PCI"
"""

RETURN = r"""
data:
  description: Details about the DLP engine retrieved.
  returned: when successful
  type: dict
  contains:
    id:
      description: The unique identifier of the DLP engine.
      returned: always
      type: int
      sample: 61
    custom_dlp_engine:
      description: Indicates whether the engine is a custom DLP engine.
      returned: always
      type: bool
      sample: false
    description:
      description: Description of what the DLP engine is used for.
      returned: always
      type: str
      sample: "Detect PCI violations"
    engine_expression:
      description: The logical expression defining the DLP engine rules.
      returned: always
      type: str
      sample: "(D63.S > 5 AND D62.S > 5)"
    predefined_engine_name:
      description: The name of the predefined engine, if this is not a custom engine.
      returned: always
      type: str
      sample: "PCI"
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    engine_id = module.params.get("id")
    engine_name = module.params.get("name")

    client = ZIAClientHelper(module)
    engines = []

    if engine_id is not None:
        engine_obj, _unused, error = client.dlp_engine.get_dlp_engines(engine_id)
        if error or engine_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve DLP Engine with ID '{engine_id}': {to_native(error)}"
            )
        engines = [engine_obj.as_dict()]
    else:
        query_params = {}
        if engine_name:
            query_params["search"] = engine_name

        result, _unused, error = client.dlp_engine.list_dlp_engines(
            query_params=query_params
        )
        if error:
            module.fail_json(msg=f"Error retrieving DLP Engines: {to_native(error)}")

        engine_list = [e.as_dict() for e in result] if result else []

        if engine_name:
            matched = next(
                (
                    e
                    for e in engine_list
                    if e.get("name") == engine_name
                    or e.get("predefined_engine_name") == engine_name
                ),
                None,
            )
            if not matched:
                available = [e.get("name") for e in engine_list]
                module.fail_json(
                    msg=f"DLP Engine with name '{engine_name}' not found. Available engines: {available}"
                )
            engines = [matched]
        else:
            engines = engine_list

    module.exit_json(changed=False, engines=engines)


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
