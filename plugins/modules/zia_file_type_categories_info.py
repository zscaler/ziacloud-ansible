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
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
# SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zia_file_type_categories_info
short_description: "Gets information about ZIA file type categories"
description:
  - "Retrieves the list of all file types, including predefined and custom file types, available for configuring rule conditions in different ZIA policies."
  - "Use the C(enums) parameter to retrieve predefined file types for specific policy categories."
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
  enums:
    description:
      - "Specifies the file type category for specific policies to retrieve the corresponding list of predefined file types supported for the policy category."
      - "C(ZSCALERDLP) - Web DLP rules with content inspection."
      - "C(EXTERNALDLP) - Web DLP rules without content inspection."
      - "C(FILETYPECATEGORYFORFILETYPECONTROL) - File Type Control policy."
    required: false
    type: list
    elements: str
    choices:
      - ZSCALERDLP
      - EXTERNALDLP
      - FILETYPECATEGORYFORFILETYPECONTROL
  exclude_custom_file_types:
    description:
      - "Whether to exclude custom file types from the list."
      - "When C(true), only predefined file types are returned."
    required: false
    type: bool
    default: false
"""

EXAMPLES = r"""
- name: Get all file type categories
  zscaler.ziacloud.zia_file_type_categories_info:
    provider: '{{ provider }}'

- name: Get file type categories for Web DLP with content inspection
  zscaler.ziacloud.zia_file_type_categories_info:
    provider: '{{ provider }}'
    enums:
      - ZSCALERDLP

- name: Get file type categories for File Type Control policy
  zscaler.ziacloud.zia_file_type_categories_info:
    provider: '{{ provider }}'
    enums:
      - FILETYPECATEGORYFORFILETYPECONTROL

- name: Get predefined file types only (exclude custom)
  zscaler.ziacloud.zia_file_type_categories_info:
    provider: '{{ provider }}'
    enums:
      - ZSCALERDLP
    exclude_custom_file_types: true
"""

RETURN = r"""
file_type_categories:
  description: List of file type categories (predefined and/or custom file types).
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
    enums = module.params.get("enums")
    exclude_custom_file_types = module.params.get("exclude_custom_file_types")

    client = ZIAClientHelper(module)

    query_params = {}
    if enums:
        query_params["enums"] = enums if isinstance(enums, list) else [enums]
    if exclude_custom_file_types is not None:
        query_params["exclude_custom_file_types"] = exclude_custom_file_types

    result, _unused, error = client.file_type_control_rule.list_file_type_categories(
        query_params=query_params if query_params else None
    )
    if error:
        module.fail_json(
            msg=f"Error retrieving file type categories: {to_native(error)}"
        )

    categories = [item.as_dict() for item in result] if result else []

    module.exit_json(changed=False, file_type_categories=categories)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        enums=dict(
            type="list",
            elements="str",
            required=False,
            choices=["ZSCALERDLP", "EXTERNALDLP", "FILETYPECATEGORYFORFILETYPECONTROL"],
        ),
        exclude_custom_file_types=dict(type="bool", required=False, default=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
