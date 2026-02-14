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
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zia_custom_file_types_info
short_description: "Gets information about ZIA custom file types"
description:
  - "Gets custom file types for File Type Control policies."
  - "Retrieves a specific custom file type by ID or name."
  - "If neither id nor name is provided, lists all custom file types."
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
      - The unique identifier for the custom file type.
    required: false
    type: int
  name:
    description:
      - The name of the custom file type.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all custom file types
  zscaler.ziacloud.zia_custom_file_types_info:
    provider: '{{ provider }}'

- name: Get a custom file type by ID
  zscaler.ziacloud.zia_custom_file_types_info:
    provider: '{{ provider }}'
    id: 1254654

- name: Get a custom file type by name
  zscaler.ziacloud.zia_custom_file_types_info:
    provider: '{{ provider }}'
    name: "My Custom File Type"
"""

RETURN = r"""
file_types:
  description: A list of custom file types fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    file_id = module.params.get("id")
    file_name = module.params.get("name")

    client = ZIAClientHelper(module)

    if file_id is not None:
        result, _unused, error = client.custom_file_types.get_custom_file_tytpe(file_id=file_id)
        if error:
            module.fail_json(msg=f"Failed to retrieve custom file type with ID '{file_id}': {to_native(error)}")
        file_types_out = [result.as_dict()]
    else:
        query_params = {"search": file_name} if file_name else {}
        result, _unused, error = client.custom_file_types.list_custom_file_types(query_params=query_params if query_params else None)
        if error:
            module.fail_json(msg=f"Error retrieving custom file types: {to_native(error)}")
        file_types_list = [f.as_dict() for f in result] if result else []

        if file_name:
            matched = next(
                (f for f in file_types_list if f.get("name") == file_name),
                None,
            )
            if matched is None:
                module.fail_json(msg=f"Custom file type with name '{file_name}' not found.")
            file_types_out = [matched]
        else:
            file_types_out = file_types_list

    module.exit_json(changed=False, file_types=file_types_out)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
