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
module: zia_cloud_firewall_network_services_groups
short_description: "Adds a new network service group."
description:
  - "Adds a new network service group."
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
    description: "A unique identifier of the network services groups"
    required: false
    type: int
  name:
    description: "The name of the network services groups"
    required: true
    type: str
  description:
    description: "The description of the network services groups"
    required: false
    type: str
  service_ids:
    type: list
    elements: int
    description: "List of network service IDs"
    required: true
"""

EXAMPLES = r"""
- name: Create/Update/Delete Network Services Groups.
  zscaler.ziacloud.zia_cloud_firewall_network_services_groups:
    provider: '{{ provider }}'
    name: "example"
    description: "example"
    service_ids:
      - name: ["UDP_ANY", "TCP_ANY"]
"""

RETURN = r"""
# The newly created network services groups resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import deleteNone
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_svc_group(group):
    """
    Normalize service group data for drift comparison.
    """
    normalized = group.copy() if group else {}
    if "service_ids" in normalized and normalized["service_ids"]:
        normalized["service_ids"] = sorted(normalized["service_ids"])
    normalized.pop("id", None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    service_group = {
        p: module.params.get(p) for p in ["id", "name", "description", "service_ids"]
    }
    group_id = service_group.get("id")
    group_name = service_group.get("name")

    existing_group = None

    if group_id:
        result, _unused, error = client.cloud_firewall.get_network_svc_group(
            group_id=group_id
        )
        if error:
            module.fail_json(
                msg=f"Error retrieving service group by ID {group_id}: {to_native(error)}"
            )
        existing_group = result.as_dict()
        if "services" in existing_group:
            existing_group["service_ids"] = sorted(
                [svc["id"] for svc in existing_group["services"]]
            )
    elif group_name:
        result, _unused, error = client.cloud_firewall.list_network_svc_groups()
        if error:
            module.fail_json(msg=f"Error listing service groups: {to_native(error)}")
        for g in result:
            group_dict = g.as_dict()
            if group_dict.get("name") == group_name:
                existing_group = group_dict
                if "services" in existing_group:
                    existing_group["service_ids"] = sorted(
                        [svc["id"] for svc in existing_group["services"]]
                    )
                break

    normalized_desired = normalize_svc_group(service_group)
    normalized_existing = normalize_svc_group(existing_group) if existing_group else {}

    differences_detected = any(
        normalized_desired[k] != normalized_existing.get(k)
        for k in normalized_desired
        if k != "id"
    )

    if module.check_mode:
        if state == "present" and (existing_group is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_group:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if existing_group:
        existing_group.update(normalized_desired)
        existing_group["id"] = existing_group.get("id") or group_id

    if state == "present":
        if existing_group:
            if differences_detected:
                group_id_to_update = existing_group.get("id")
                if not group_id_to_update:
                    module.fail_json(msg="Cannot update service group: ID is missing.")

                payload = deleteNone(
                    dict(
                        group_id=group_id_to_update,
                        name=service_group.get("name"),
                        service_ids=service_group.get("service_ids"),
                        description=service_group.get("description"),
                    )
                )

                updated_group, _unused, error = (
                    client.cloud_firewall.update_network_svc_group(**payload)
                )
                if error:
                    module.fail_json(
                        msg=f"Error updating service group: {to_native(error)}"
                    )
                module.exit_json(changed=True, data=updated_group.as_dict())
            else:
                module.exit_json(changed=False, data=existing_group)
        else:
            payload = deleteNone(
                dict(
                    name=service_group.get("name"),
                    service_ids=service_group.get("service_ids"),
                    description=service_group.get("description"),
                )
            )

            created_group, _unused, error = client.cloud_firewall.add_network_svc_group(
                **payload
            )
            if error:
                module.fail_json(
                    msg=f"Error creating service group: {to_native(error)}"
                )
            module.exit_json(changed=True, data=created_group.as_dict())

    elif state == "absent":
        if existing_group:
            group_id_to_delete = existing_group.get("id")
            if not group_id_to_delete:
                module.fail_json(msg="Cannot delete service group: ID is missing.")

            _unused, _unused, error = client.cloud_firewall.delete_network_svc_group(
                group_id=group_id_to_delete
            )
            if error:
                module.fail_json(
                    msg=f"Error deleting service group: {to_native(error)}"
                )
            module.exit_json(changed=True, data=existing_group)
        else:
            module.exit_json(changed=False, data={})

    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        service_ids=dict(type="list", elements="int", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
