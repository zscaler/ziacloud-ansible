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
module: zia_bandwidth_classes
short_description: "Adds a new bandwidth class"
description:
  - "Adds a new bandwidth class"
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
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
    description: "The unique identifier for the bandwidth class."
    type: int
  name:
    description: "The bandwidth class name."
    required: true
    type: str
  url_categories:
    description:
      - The URL categories to which the rule applies
      - Use the info resource zia_url_categories_info to retrieve the category names.
    required: false
    type: list
    elements: str
  urls:
    description:
      - The URLs included in the bandwidth class. You can include multiple entries.
    required: false
    type: list
    elements: str
  web_applications:
    description:
      - The web conferencing applications included in the bandwidth class.
      - Use the info resource zia_cloud_applications_info to retrieve the application names.
    required: false
    type: list
    elements: str
"""

EXAMPLES = r"""

- name: Create/Update/Delete bandwidth class.
  zscaler.ziacloud.zia_bandwidth_classes:
    provider: '{{ provider }}'
    name: "Example"
    url_categories:
      - AI_ML_APPS
      - GENERAL_AI_ML
    urls:
      - test1.acme.com
      - test2.acme.com
    web_applications:
      - ACADEMICGPT
      - AD_CREATIVES
"""

RETURN = r"""
# The newly created bandwidth class resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_classes(bdw_class):
    """
    Remove computed attributes from a badwidth classes dict to make comparison easier.
    """
    normalized = bdw_class.copy() if bdw_class else {}
    computed_values = ["id"]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    bdw_class_params = {
        p: module.params.get(p)
        for p in [
            "id",
            "name",
            "web_applications",
            "url_categories",
            "urls",
        ]
    }
    bwd_id = bdw_class_params.get("id")
    class_name = bdw_class_params.get("name")

    existing_class = None

    if bwd_id:
        result, _unused, error = client.bandwidth_classes.get_class(bwd_id)
        if error:
            module.fail_json(msg=f"Error fetching class with id {bwd_id}: {to_native(error)}")
        existing_class = result.as_dict()
    else:
        result, _unused, error = client.bandwidth_classes.list_classes()
        if error:
            module.fail_json(msg=f"Error listing classes: {to_native(error)}")
        classes_list = [bdw_class.as_dict() for bdw_class in result]
        if class_name:
            for bdw_class in classes_list:
                if bdw_class.get("name") == class_name:
                    existing_class = bdw_class
                    break

    normalized_desired = normalize_classes(bdw_class_params)
    normalized_existing = normalize_classes(existing_class) if existing_class else {}

    differences_detected = False
    unordered_fields = ["applications", "urls", "url_categories", "web_applications"]

    for key, desired_value in normalized_desired.items():
        current_value = normalized_existing.get(key)

        if key in unordered_fields and isinstance(desired_value, list) and isinstance(current_value, list):
            if set(map(str, desired_value)) != set(map(str, current_value)):
                differences_detected = True
                module.warn(f"Difference detected in {key} (unordered). Current: {current_value}, Desired: {desired_value}")
        else:
            if current_value != desired_value:
                differences_detected = True
                module.warn(f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}")

    if module.check_mode:
        if state == "present" and (existing_class is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_class:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_class:
            if differences_detected:
                bwd_id_to_update = existing_class.get("id")
                if not bwd_id_to_update:
                    module.fail_json(msg="Cannot update class: ID is missing from the existing resource.")

                updated_class, _unused, error = client.bandwidth_classes.update_class(
                    bwd_id=bwd_id_to_update,
                    name=bdw_class_params.get("name"),
                    web_applications=bdw_class_params.get("web_applications"),
                    url_categories=bdw_class_params.get("url_categories"),
                    urls=bdw_class_params.get("urls"),
                )
                if error:
                    module.fail_json(msg=f"Error updating class: {to_native(error)}")
                module.exit_json(changed=True, data=updated_class.as_dict())
            else:
                module.exit_json(changed=False, data=existing_class)
        else:
            new_class, _unused, error = client.bandwidth_classes.add_class(
                name=bdw_class_params.get("name"),
                web_applications=bdw_class_params.get("web_applications"),
                url_categories=bdw_class_params.get("url_categories"),
                urls=bdw_class_params.get("urls"),
            )
            if error:
                module.fail_json(msg=f"Error adding class: {to_native(error)}")
            module.exit_json(changed=True, data=new_class.as_dict())

    elif state == "absent":
        if existing_class:
            bwd_id_to_delete = existing_class.get("id")
            if not bwd_id_to_delete:
                module.fail_json(msg="Cannot delete class: ID is missing from the existing resource.")

            _unused, _unused, error = client.bandwidth_classes.delete_class(bwd_id_to_delete)
            if error:
                module.fail_json(msg=f"Error deleting class: {to_native(error)}")
            module.exit_json(changed=True, data=existing_class)
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
            web_applications=dict(type="list", elements="str", required=False),
            url_categories=dict(type="list", elements="str", required=False),
            urls=dict(type="list", elements="str", required=False),
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
