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
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zia_workload_groups
short_description: "Manages ZIA workload groups"
description:
  - "Creates, updates, or deletes workload groups in Zscaler Internet Access."
  - "Workload groups define a set of workloads based on tag expressions for use in ZIA policies."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
  - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
  - Check mode is supported.
  - Use C(id) or C(name) to reference an existing workload group for update/delete.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description:
      - The unique identifier for the workload group.
      - Used to reference an existing group for update or delete.
    required: false
    type: int
  name:
    description:
      - The name of the workload group.
      - Required for create; use with C(id) for update/delete by ID.
    required: false
    type: str
  description:
    description:
      - Additional information about the workload group.
    required: false
    type: str
  expression_json:
    description:
      - JSON structure defining the workload tag expression.
      - Contains expression_containers with tag rules.
    required: false
    type: list
    elements: dict
    suboptions:
      expression_containers:
        description: List of expression containers defining tag matching rules.
        type: list
        elements: dict
        suboptions:
          tag_type:
            description: Type of tag (e.g. VPC, SUBNET, VM, ENI, ATTR).
            type: str
            choices:
              - ANY
              - VPC
              - SUBNET
              - VM
              - ENI
              - ATTR
          operator:
            description: Logical operator for the expression.
            type: str
            choices:
              - AND
              - OR
              - OPEN_PARENTHESES
              - CLOSE_PARENTHESES
          tag_container:
            description: Container for tags with matching criteria.
            type: list
            elements: dict
            suboptions:
              tags:
                description: List of tag key/value pairs.
                type: list
                elements: dict
                suboptions:
                  key:
                    description: Tag key identifier.
                    type: str
                  value:
                    description: Tag value.
                    type: str
              operator:
                description: Logical operator for tags within the container.
                type: str
                choices:
                  - AND
                  - OR
                  - OPEN_PARENTHESES
                  - CLOSE_PARENTHESES
"""

EXAMPLES = r"""
- name: Create a workload group with expression
  zscaler.ziacloud.zia_workload_groups:
    provider: '{{ provider }}'
    name: "ATTR Workload Group"
    description: "Match by attribute"
    expression_json:
      - expression_containers:
          - tag_type: ATTR
            operator: AND
            tag_container:
              - tags:
                  - key: GroupName
                    value: example
                operator: AND
"""

RETURN = r"""
data:
  description: The workload group resource record.
  returned: on success
  type: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def _normalize_expression(ej):
    """Normalize expression_json for comparison (sorted tags, stable structure)."""
    if not ej:
        return None
    if isinstance(ej, list) and len(ej) > 0:
        ej = ej[0]
    if not isinstance(ej, dict):
        return ej
    out = {}
    containers = ej.get("expression_containers") or []
    out["expression_containers"] = []
    for c in containers:
        nc = {"tag_type": c.get("tag_type"), "operator": c.get("operator")}
        tc_raw = c.get("tag_container")
        tc = None
        if isinstance(tc_raw, list) and tc_raw:
            tc = tc_raw[0] if isinstance(tc_raw[0], dict) else {}
        elif isinstance(tc_raw, dict):
            tc = tc_raw
        if tc:
            tags = tc.get("tags") or []
            nc["tag_container"] = [{
                "operator": tc.get("operator"),
                "tags": sorted(
                    [{"key": t.get("key"), "value": t.get("value")} for t in tags],
                    key=lambda x: (x.get("key") or "", x.get("value") or ""),
                ),
            }]
        out["expression_containers"].append(nc)
    return out


def _normalize_group(group):
    """Normalize group dict for idempotency (exclude computed fields)."""
    if not group:
        return {}
    out = {
        "name": group.get("name"),
        "description": group.get("description") or "",
        "expression_json": _normalize_expression(group.get("expression_json")),
    }
    return out


def _build_expression_json(expr_list):
    """Build expression_json dict for API from module params."""
    if not expr_list or not isinstance(expr_list, list) or len(expr_list) == 0:
        return None
    top = expr_list[0] if isinstance(expr_list[0], dict) else {}
    containers = top.get("expression_containers") or []
    if not containers:
        return None
    expression_containers = []
    for c in containers:
        ec = {
            "tag_type": c.get("tag_type") or "ANY",
            "operator": c.get("operator") or "AND",
        }
        tc_list = c.get("tag_container") or []
        if tc_list:
            tc = tc_list[0] if isinstance(tc_list[0], dict) else {}
            tags = [{"key": t.get("key"), "value": t.get("value")} for t in (tc.get("tags") or [])]
            ec["tag_container"] = {"operator": tc.get("operator") or "AND", "tags": tags}
        expression_containers.append(ec)
    return {"expression_containers": expression_containers}


def _build_payload(params, existing=None):
    """Build payload for add/update."""
    payload = {
        "name": params.get("name"),
        "description": params.get("description") or "",
    }
    expr = params.get("expression_json")
    if expr is not None:
        built = _build_expression_json(expr)
        payload["expression_json"] = built
    elif existing:
        payload["expression_json"] = existing.get("expression_json")
    if existing and existing.get("id") is not None:
        payload["id"] = existing["id"]
    return payload


def core(module):
    state = module.params.get("state")
    group_id = module.params.get("id")
    group_name = module.params.get("name")

    client = ZIAClientHelper(module)

    existing = None
    if group_id is not None:
        result, _unused, error = client.workload_groups.get_group(group_id)
        if error:
            module.fail_json(
                msg=f"Error fetching workload group with id {group_id}: {to_native(error)}"
            )
        existing = result.as_dict()
    else:
        result, _unused, error = client.workload_groups.list_groups()
        if error:
            module.fail_json(
                msg=f"Error listing workload groups: {to_native(error)}"
            )
        groups_list = [g.as_dict() for g in result] if result else []
        if group_name:
            for g in groups_list:
                if (g.get("name") or "").lower() == (group_name or "").lower():
                    existing = g
                    break

    desired = _build_payload(module.params, existing)
    normalized_desired = _normalize_group(desired)
    normalized_existing = _normalize_group(existing) if existing else {}
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
                    module.fail_json(
                        msg="Cannot update: ID is missing from the existing workload group."
                    )
                update_params = {
                    "name": desired.get("name"),
                    "description": desired.get("description"),
                }
                if "expression_json" in desired and desired["expression_json"] is not None:
                    update_params["expression_json"] = desired["expression_json"]
                updated, _unused, error = client.workload_groups.update_group(
                    id_to_update, **update_params
                )
                if error:
                    module.fail_json(
                        msg=f"Error updating workload group: {to_native(error)}"
                    )
                module.exit_json(changed=True, data=updated.as_dict())
            else:
                module.exit_json(changed=False, data=existing)
        else:
            if not group_name:
                module.fail_json(msg="Name is required for create.")
            add_params = {
                "name": desired.get("name"),
                "description": desired.get("description"),
            }
            if desired.get("expression_json"):
                add_params["expression_json"] = desired["expression_json"]
            new_group, _unused, error = client.workload_groups.add_group(**add_params)
            if error:
                module.fail_json(
                    msg=f"Error creating workload group: {to_native(error)}"
                )
            module.exit_json(changed=True, data=new_group.as_dict())

    elif state == "absent":
        if existing:
            id_to_delete = existing.get("id")
            if not id_to_delete:
                module.fail_json(
                    msg="Cannot delete: ID is missing from the existing workload group."
                )
            _unused, _unused, error = client.workload_groups.delete_group(id_to_delete)
            if error:
                module.fail_json(
                    msg=f"Error deleting workload group: {to_native(error)}"
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
            expression_json=dict(type="list", elements="dict", required=False),
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
