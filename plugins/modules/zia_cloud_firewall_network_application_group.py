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
module: zia_cloud_firewall_network_application_group
short_description: "Cloud Firewall Network Application Group"
description:
  - "Creates a new custom network application group."
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
    description: "A unique identifier of the network application groups"
    required: false
    type: int
  name:
    description: "The name of the network application groups"
    required: true
    type: str
  description:
    description: "The description of the network application groups"
    required: false
    type: str
  network_applications:
    description: "List of applications in the network application group"
    type: list
    elements: str
    required: true
"""

EXAMPLES = r"""
- name: Create/Update/Delete network application group.
  zscaler.ziacloud.zia_cloud_firewall_network_application_group:
    provider: '{{ provider }}'
    name: "sampleNetworkApplicationGroup"
    network_applications:
      - 'YAMMER'
      - 'OFFICE365'
      - 'SKYPE_FOR_BUSINESS'
      - 'OUTLOOK'
      - 'SHAREPOINT'
      - 'SHAREPOINT_ADMIN'
      - 'SHAREPOINT_BLOG'
      - 'SHAREPOINT_CALENDAR'
      - 'SHAREPOINT_DOCUMENT'
      - 'SHAREPOINT_ONLINE'
      - 'ONEDRIVE'
"""

RETURN = r"""
# The newly created network application group resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_group(group):
    """
    Remove computed attributes from a group dict to make comparison easier.
    """
    normalized = group.copy() if group else {}
    computed_values = ["id"]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    group_params = {
        p: module.params.get(p)
        for p in ["id", "name", "description", "network_applications"]
    }
    group_id = group_params.get("id")
    group_name = group_params.get("name")

    existing_group = None

    if group_id:
        result, _unused, error = client.cloud_firewall.get_network_app_group(group_id)
        if error:
            module.fail_json(
                msg=f"Error fetching ip source group with id {group_id}: {to_native(error)}"
            )
        existing_group = result.as_dict()
    else:
        result, _unused, error = client.cloud_firewall.list_network_app_groups()
        if error:
            module.fail_json(msg=f"Error listing groups: {to_native(error)}")
        group_list = [group.as_dict() for group in result]
        if group_name:
            for group in group_list:
                if group.get("name") == group_name:
                    existing_group = group
                    break

    normalized_desired = normalize_group(group_params)
    normalized_existing = normalize_group(existing_group) if existing_group else {}

    differences_detected = False
    for key, value in normalized_desired.items():
        if normalized_existing.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing.get(key)}, Desired: {value}"
            )

    if module.check_mode:
        if state == "present" and (existing_group is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_group:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_group:
            if differences_detected:
                group_id_to_update = existing_group.get("id")
                if not group_id_to_update:
                    module.fail_json(
                        msg="Cannot update group: ID is missing from the existing resource."
                    )

                update_group, _unused, error = (
                    client.cloud_firewall.update_network_app_group(
                        group_id=group_id_to_update,
                        name=group_params.get("name"),
                        description=group_params.get("description"),
                        network_applications=group_params.get("network_applications"),
                    )
                )
                if error:
                    module.fail_json(msg=f"Error updating group: {to_native(error)}")
                module.exit_json(changed=True, data=update_group.as_dict())
            else:
                module.exit_json(changed=False, data=existing_group)
        else:
            new_group, _unused, error = client.cloud_firewall.add_network_app_group(
                name=group_params.get("name"),
                description=group_params.get("description"),
                network_applications=group_params.get("network_applications"),
            )
            if error:
                module.fail_json(msg=f"Error adding group: {to_native(error)}")
            module.exit_json(changed=True, data=new_group.as_dict())

    elif state == "absent":
        if existing_group:
            group_id_to_delete = existing_group.get("id")
            if not group_id_to_delete:
                module.fail_json(msg="Cannot delete network app group: ID is missing")

            _unused, _unused, error = client.cloud_firewall.delete_network_app_group(
                group_id_to_delete
            )
            if error:
                module.fail_json(msg=f"Error deleting group: {to_native(error)}")
            module.exit_json(changed=True, data=existing_group)
        else:
            module.exit_json(changed=False, data={})

    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        network_applications=dict(type="list", elements="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
