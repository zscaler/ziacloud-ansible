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
module: zia_extranet
short_description: "Manages ZIA extranet configurations"
description:
  - "Adds, updates, or removes extranet configurations for traffic forwarding."
  - "Extranets define DNS servers and IP pools for traffic selectors."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
    - Use C(id) or C(name) to reference an existing extranet for update/delete.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description:
      - The unique identifier for the extranet.
      - Used to reference an existing extranet for update or delete.
    required: false
    type: int
  name:
    description:
      - The name of the extranet.
      - Required for create. Maximum 255 characters.
    required: true
    type: str
  description:
    description:
      - The description of the extranet.
      - Maximum 10240 characters.
    required: false
    type: str
  extranet_dns_list:
    description:
      - DNS servers specified for the extranet.
    required: false
    type: list
    elements: dict
    suboptions:
      id:
        description: The ID for an existing DNS config (update only).
        type: int
      name:
        description: The name of the DNS server.
        required: true
        type: str
      primary_dns_server:
        description: The IP address of the primary DNS server.
        required: true
        type: str
      secondary_dns_server:
        description: The IP address of the secondary DNS server.
        type: str
      use_as_default:
        description: Whether this DNS configuration is the designated default.
        type: bool
        default: false
  extranet_ip_pool_list:
    description:
      - Traffic selector IP pools specified for the extranet.
    required: false
    type: list
    elements: dict
    suboptions:
      id:
        description: The ID for an existing IP pool (update only).
        type: int
      name:
        description: The name of the IP pool.
        required: true
        type: str
      ip_start:
        description: The starting IP address of the pool.
        required: true
        type: str
      ip_end:
        description: The ending IP address of the pool.
        required: true
        type: str
      use_as_default:
        description: Whether this IP pool is the designated default.
        type: bool
        default: false
"""

EXAMPLES = r"""
- name: Create an extranet
  zscaler.ziacloud.zia_extranet:
    provider: '{{ provider }}'
    name: "My Extranet"
    description: "Extranet for branch offices"
    extranet_dns_list:
      - name: "DNS Primary"
        primary_dns_server: "8.8.8.8"
        secondary_dns_server: "4.4.2.2"
        use_as_default: true
    extranet_ip_pool_list:
      - name: "Pool 1"
        ip_start: "192.168.200.1"
        ip_end: "192.168.200.100"
        use_as_default: true

- name: Update an extranet by ID
  zscaler.ziacloud.zia_extranet:
    provider: '{{ provider }}'
    id: 12345
    name: "Updated Extranet Name"
    description: "Updated description"

- name: Delete an extranet
  zscaler.ziacloud.zia_extranet:
    provider: '{{ provider }}'
    id: 12345
    state: absent
"""

RETURN = r"""
data:
  description: The extranet resource record.
  returned: on success
  type: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def _normalize_dns_list(lst):
    """Normalize DNS list for comparison (order by name, exclude id)."""
    if not lst:
        return []
    out = []
    for item in lst if isinstance(lst, list) else []:
        d = dict(item)
        d.pop("id", None)
        out.append(d)
    return sorted(out, key=lambda x: (x.get("name") or "", str(x)))


def _normalize_ip_pool_list(lst):
    """Normalize IP pool list for comparison (order by name, exclude id)."""
    if not lst:
        return []
    out = []
    for item in lst if isinstance(lst, list) else []:
        d = dict(item)
        d.pop("id", None)
        out.append(d)
    return sorted(out, key=lambda x: (x.get("name") or "", str(x)))


def _build_dns_list(items):
    """Build DNS list for SDK (include id when present for update)."""
    if not items:
        return []
    out = []
    for item in items:
        d = {
            "name": item.get("name"),
            "primary_dns_server": item.get("primary_dns_server"),
            "secondary_dns_server": item.get("secondary_dns_server") or "",
            "use_as_default": item.get("use_as_default") or False,
        }
        if item.get("id"):
            d["id"] = item["id"]
        out.append(d)
    return out


def _build_ip_pool_list(items):
    """Build IP pool list for SDK (include id when present for update)."""
    if not items:
        return []
    out = []
    for item in items:
        d = {
            "name": item.get("name"),
            "ip_start": item.get("ip_start"),
            "ip_end": item.get("ip_end"),
            "use_as_default": item.get("use_as_default") or False,
        }
        if item.get("id"):
            d["id"] = item["id"]
        out.append(d)
    return out


def normalize_extranet(extranet):
    """Normalize extranet dict for idempotency comparison."""
    if not extranet:
        return {}
    norm = {
        "name": extranet.get("name"),
        "description": extranet.get("description") or "",
        "extranet_dns_list": _normalize_dns_list(
            extranet.get("extranet_dns_list")
        ),
        "extranet_ip_pool_list": _normalize_ip_pool_list(
            extranet.get("extranet_ip_pool_list")
        ),
    }
    return norm


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    extranet_id = module.params.get("id")
    extranet_name = module.params.get("name")
    description = module.params.get("description")
    extranet_dns_list = module.params.get("extranet_dns_list")
    extranet_ip_pool_list = module.params.get("extranet_ip_pool_list")

    desired = {
        "name": extranet_name,
        "description": description or "",
        "extranet_dns_list": _normalize_dns_list(extranet_dns_list),
        "extranet_ip_pool_list": _normalize_ip_pool_list(extranet_ip_pool_list),
    }

    existing_extranet = None

    if extranet_id is not None:
        result, _unused, error = client.traffic_extranet.get_extranet(
            extranet_id
        )
        if error:
            module.fail_json(
                msg=f"Error fetching extranet with id {extranet_id}: {to_native(error)}"
            )
        existing_extranet = result.as_dict()
    else:
        result, _unused, error = client.traffic_extranet.list_extranets(
            query_params={"pageSize": 500}
        )
        if error:
            module.fail_json(
                msg=f"Error listing extranets: {to_native(error)}"
            )
        extranets_list = [e.as_dict() for e in result] if result else []
        if extranet_name:
            for e in extranets_list:
                if e.get("name", "").lower() == extranet_name.lower():
                    existing_extranet = e
                    break

    normalized_desired = normalize_extranet(desired)
    normalized_existing = (
        normalize_extranet(existing_extranet) if existing_extranet else {}
    )

    differences_detected = normalized_desired != normalized_existing

    if module.check_mode:
        if state == "present" and (existing_extranet is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_extranet:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_extranet:
            if differences_detected:
                id_to_update = existing_extranet.get("id")
                if not id_to_update:
                    module.fail_json(
                        msg="Cannot update: ID is missing from the existing extranet."
                    )
                # Merge existing DNS/pool with user params to preserve IDs
                existing_dns = existing_extranet.get("extranet_dns_list") or []
                existing_pools = existing_extranet.get("extranet_ip_pool_list") or []
                dns_by_name = {d.get("name"): d for d in existing_dns if d.get("name")}
                pool_by_name = {p.get("name"): p for p in existing_pools if p.get("name")}
                merged_dns = []
                for d in extranet_dns_list or []:
                    entry = dict(d)
                    if d.get("name") and d.get("name") in dns_by_name:
                        entry["id"] = dns_by_name[d["name"]].get("id")
                    merged_dns.append(entry)
                merged_pools = []
                for p in extranet_ip_pool_list or []:
                    entry = dict(p)
                    if p.get("name") and p.get("name") in pool_by_name:
                        entry["id"] = pool_by_name[p["name"]].get("id")
                    merged_pools.append(entry)
                update_params = {
                    "name": extranet_name,
                    "description": description or "",
                    "extranet_dns_list": _build_dns_list(merged_dns),
                    "extranet_ip_pool_list": _build_ip_pool_list(merged_pools),
                }
                updated, _unused, error = client.traffic_extranet.update_extranet(
                    id_to_update,
                    **update_params,
                )
                if error:
                    module.fail_json(
                        msg=f"Error updating extranet: {to_native(error)}"
                    )
                module.exit_json(changed=True, data=updated.as_dict())
            else:
                module.exit_json(changed=False, data=existing_extranet)
        else:
            add_params = {
                "name": extranet_name,
                "description": description or "",
                "extranet_dns_list": _build_dns_list(extranet_dns_list),
                "extranet_ip_pool_list": _build_ip_pool_list(extranet_ip_pool_list),
            }
            new_extranet, _unused, error = client.traffic_extranet.add_extranet(
                **add_params
            )
            if error:
                module.fail_json(
                    msg=f"Error adding extranet: {to_native(error)}"
                )
            module.exit_json(changed=True, data=new_extranet.as_dict())

    elif state == "absent":
        if existing_extranet:
            id_to_delete = existing_extranet.get("id")
            if not id_to_delete:
                module.fail_json(
                    msg="Cannot delete: ID is missing from the existing extranet."
                )
            _unused, _unused, error = client.traffic_extranet.delete_extranet(
                id_to_delete
            )
            if error:
                module.fail_json(
                    msg=f"Error deleting extranet: {to_native(error)}"
                )
            module.exit_json(changed=True, data=existing_extranet)
        else:
            module.exit_json(changed=False, data={})
    else:
        module.exit_json(changed=False, data={})


def main():
    dns_subspec = {
        "id": dict(type="int", required=False),
        "name": dict(type="str", required=True),
        "primary_dns_server": dict(type="str", required=True),
        "secondary_dns_server": dict(type="str", required=False),
        "use_as_default": dict(type="bool", required=False, default=False),
    }
    pool_subspec = {
        "id": dict(type="int", required=False),
        "name": dict(type="str", required=True),
        "ip_start": dict(type="str", required=True),
        "ip_end": dict(type="str", required=True),
        "use_as_default": dict(type="bool", required=False, default=False),
    }
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            id=dict(type="int", required=False),
            name=dict(type="str", required=True),
            description=dict(type="str", required=False),
            extranet_dns_list=dict(
                type="list",
                elements="dict",
                options=dns_subspec,
                required=False,
            ),
            extranet_ip_pool_list=dict(
                type="list",
                elements="dict",
                options=pool_subspec,
                required=False,
            ),
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
