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
module: zia_bandwidth_classes_info
short_description: "Retrieves a list of bandwidth classes for an organization"
description:
  - "Retrieves a list of bandwidth classes for an organization"
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  id:
    description: "The unique identifier for the Bandwidth Class"
    type: int
    required: false
  name:
    description: "The Name of the bandwidth class name."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets all list of bandwidth class
  zscaler.ziacloud.zia_bandwidth_classes_info:
    provider: '{{ provider }}'

- name: Gets a list of bandwidth class by name
  zscaler.ziacloud.zia_bandwidth_classes_info:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
classes:
  description: A list of bandwidth classes fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the Bandwidth Class
      returned: always
      type: int
      sample: 3687131
    name:
      description: The name of the Bandwidth Class
      returned: always
      type: str
      sample: "Example"
    url_categories:
      description: The URL categories to add to the bandwidth class
      type: list
      elements: str
      returned: always
      sample: ["PROFESSIONAL_SERVICES", "AI_ML_APPS", "GENERAL_AI_ML"]
    web_applications:
      description: The web conferencing applications included in the bandwidth class.
      type: list
      elements: str
      returned: always
      sample: ["ACADEMICGPT", "AD_CREATIVES"]
    urls:
      description: The URLs included in the bandwidth class
      type: list
      elements: str
      returned: always
      sample: ["test1.acme.com", "test2.acme.com"]
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    class_id = module.params.get("id")
    class_name = module.params.get("name")

    client = ZIAClientHelper(module)
    classes = []

    if class_id is not None:
        class_obj, _unused, error = client.bandwidth_classes.get_class(class_id)
        if error or class_obj is None:
            module.fail_json(msg=f"Failed to retrieve Bandwidth Class with ID '{class_id}': {to_native(error)}")
        classes = [class_obj.as_dict()]
    else:
        query_params = {}
        if class_name:
            query_params["search"] = class_name

        result, _unused, error = client.bandwidth_classes.list_classes(query_params=query_params)
        if error:
            module.fail_json(msg=f"Error retrieving Bandwidth Classes: {to_native(error)}")

        class_list = [g.as_dict() for g in result] if result else []

        if class_name:
            matched = next((g for g in class_list if g.get("name") == class_name), None)
            if not matched:
                available = [g.get("name") for g in class_list]
                module.fail_json(msg=f"Bandwidth Class with name '{class_name}' not found. Available classes: {available}")
            classes = [matched]
        else:
            classes = class_list

    module.exit_json(changed=False, classes=classes)


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
