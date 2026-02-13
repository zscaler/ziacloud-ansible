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
module: zia_custom_file_types
short_description: "Manages ZIA custom file types"
description:
  - "Creates, updates, or deletes custom file types for File Type Control policies."
  - "Custom file types can be configured as rule conditions in different ZIA policies."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
    - Use C(id) or C(name) to reference an existing custom file type for update/delete.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description:
      - The unique identifier for the custom file type.
      - Used to reference an existing custom file type for update or delete.
    required: false
    type: int
  name:
    description:
      - The name of the custom file type.
    required: false
    type: str
  description:
    description:
      - Additional information about the custom file type.
    required: false
    type: str
  extension:
    description:
      - The file type extension. Maximum 10 characters.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Create a custom file type
  zscaler.ziacloud.zia_custom_file_types:
    provider: '{{ provider }}'
    name: "My Custom Extension"
    description: "Custom file type for internal use"
    extension: "myext"

- name: Update a custom file type by ID
  zscaler.ziacloud.zia_custom_file_types:
    provider: '{{ provider }}'
    id: 1254654
    name: "My Custom Extension Updated"
    description: "Updated description"

- name: Delete a custom file type
  zscaler.ziacloud.zia_custom_file_types:
    provider: '{{ provider }}'
    id: 1254654
    state: absent
"""

RETURN = r"""
data:
  description: The custom file type resource record.
  returned: on success
  type: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_file_type(ft):
    """Normalize custom file type for idempotency comparison."""
    if not ft:
        return {}
    return {
        "name": ft.get("name") or "",
        "description": ft.get("description") or "",
        "extension": ft.get("extension") or "",
    }


def core(module):
    state = module.params.get("state")
    file_id = module.params.get("id")
    file_name = module.params.get("name")
    description = module.params.get("description")
    extension = module.params.get("extension")

    client = ZIAClientHelper(module)

    existing = None
    if file_id is not None:
        result, _unused, error = client.custom_file_types.get_custom_file_tytpe(
            file_id=file_id
        )
        if error:
            module.fail_json(
                msg=f"Error fetching custom file type with id {file_id}: {to_native(error)}"
            )
        existing = result.as_dict()
    else:
        result, _unused, error = client.custom_file_types.list_custom_file_types(
            query_params={"search": file_name} if file_name else None
        )
        if error:
            module.fail_json(
                msg=f"Error listing custom file types: {to_native(error)}"
            )
        types_list = [f.as_dict() for f in result] if result else []
        if file_name:
            for f in types_list:
                if f.get("name", "").lower() == file_name.lower():
                    existing = f
                    break

    desired = {
        "name": file_name or "",
        "description": description or "",
        "extension": extension or "",
    }
    if existing:
        desired["name"] = desired["name"] or existing.get("name") or ""
        desired["description"] = desired["description"] if description is not None else (existing.get("description") or "")
        desired["extension"] = desired["extension"] if extension is not None else (existing.get("extension") or "")

    normalized_desired = normalize_file_type(desired)
    normalized_existing = normalize_file_type(existing) if existing else {}
    differences = normalized_desired != normalized_existing

    if module.check_mode:
        if state == "present" and (existing is None or differences):
            module.exit_json(changed=True)
        elif state == "absent" and existing:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing:
            if differences:
                id_to_update = existing.get("id")
                if not id_to_update:
                    module.fail_json(msg="Cannot update: ID is missing from the existing custom file type.")
                update_params = {
                    "name": desired["name"],
                    "description": desired["description"],
                    "extension": desired["extension"],
                }
                updated, _unused, error = client.custom_file_types.update_custom_file_type(
                    id_to_update, **update_params
                )
                if error:
                    module.fail_json(
                        msg=f"Error updating custom file type: {to_native(error)}"
                    )
                module.exit_json(changed=True, data=updated.as_dict())
            else:
                module.exit_json(changed=False, data=existing)
        else:
            if not file_name and not extension:
                module.fail_json(
                    msg="At least one of 'name' or 'extension' is required for create."
                )
            add_params = {
                "name": desired["name"] or desired["extension"],
                "description": desired["description"],
                "extension": desired["extension"],
            }
            new_ft, _unused, error = client.custom_file_types.add_custom_file_type(
                **add_params
            )
            if error:
                module.fail_json(
                    msg=f"Error creating custom file type: {to_native(error)}"
                )
            module.exit_json(changed=True, data=new_ft.as_dict())

    elif state == "absent":
        if existing:
            id_to_delete = existing.get("id")
            if not id_to_delete:
                module.fail_json(msg="Cannot delete: ID is missing from the existing custom file type.")
            _unused, _unused, error = client.custom_file_types.delete_custom_file_type(
                id_to_delete
            )
            if error:
                module.fail_json(
                    msg=f"Error deleting custom file type: {to_native(error)}"
                )
            module.exit_json(changed=True, data=existing)
        else:
            module.exit_json(changed=False, data={})
    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            id=dict(type="int", required=False),
            name=dict(type="str", required=False),
            description=dict(type="str", required=False),
            extension=dict(type="str", required=False),
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
