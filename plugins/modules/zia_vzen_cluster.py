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
module: zia_vzen_cluster
short_description: "Manages Virtual Service Edge clusters"
description:
  - "Adds, updates, or removes Virtual Service Edge (VZEN) clusters."
  - "Clusters group Virtual Service Edge instances for traffic forwarding."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
    - Use C(id) or C(name) to reference an existing cluster for update/delete.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description:
      - System-generated Virtual Service Edge cluster ID.
      - Used to reference an existing cluster for update or delete.
    required: false
    type: int
  name:
    description:
      - Name of the Virtual Service Edge cluster.
      - Required for create.
    required: true
    type: str
  status:
    description:
      - Specifies the status of the Virtual Service Edge cluster.
      - Default is ENABLED.
    required: false
    type: str
    choices:
      - ENABLED
      - DISABLED
      - DISABLED_BY_SERVICE_PROVIDER
      - NOT_PROVISIONED_IN_SERVICE_PROVIDER
  type:
    description:
      - The Virtual Service Edge cluster type.
    required: false
    type: str
    choices:
      - ANY
      - NONE
      - SME
      - SMSM
      - SMCA
      - SMUI
      - SMCDS
      - SMDNSD
      - SMAA
      - SMTP
      - SMQTN
      - VIP
      - UIZ
      - UIAE
      - SITEREVIEW
      - PAC
      - S_RELAY
      - M_RELAY
      - H_MON
      - SMIKE
      - NSS
      - SMEZA
      - SMLB
      - SMFCCLT
      - SMBA
      - SMBAC
      - SMESXI
      - SMBAUI
      - VZEN
      - ZSCMCLT
      - SMDLP
      - ZSQUERY
      - ADP
      - SMCDSDLP
      - SMSCIM
      - ZSAPI
      - ZSCMCDSSCLT
      - LOCAL_MTS
      - SVPN
      - SMCASB
      - SMFALCONUI
      - MOBILEAPP_REG
      - SMRESTSVR
      - FALCONCA
      - MOBILEAPP_NF
      - ZIRSVR
      - SMEDGEUI
      - ALERTEVAL
      - ALERTNOTIF
      - SMPARTNERUI
      - CQM
      - DATAKEEPER
      - SMBAM
      - ZWACLT
  ip_sec_enabled:
    description:
      - Whether to terminate IPSec traffic at selected Virtual Service Edge instances.
    required: false
    type: bool
  ip_address:
    description:
      - The Virtual Service Edge cluster IP address.
    required: false
    type: str
  subnet_mask:
    description:
      - The Virtual Service Edge cluster subnet mask.
    required: false
    type: str
  default_gateway:
    description:
      - The IP address of the default gateway to the internet.
    required: false
    type: str
  virtual_zen_node_ids:
    description:
      - List of Virtual Service Edge node IDs to include in the cluster.
    required: false
    type: list
    elements: int
"""

EXAMPLES = r"""
- name: Create a VZEN cluster
  zscaler.ziacloud.zia_vzen_cluster:
    provider: '{{ provider }}'
    name: "VZEN-Cluster-01"
    status: ENABLED
    ip_address: "192.168.100.100"
    subnet_mask: "255.255.255.0"
    default_gateway: "192.168.100.1"
    ip_sec_enabled: true
    virtual_zen_node_ids:
      - 123456
      - 123457

- name: Update a VZEN cluster by ID
  zscaler.ziacloud.zia_vzen_cluster:
    provider: '{{ provider }}'
    id: 1254654
    name: "VZEN-Cluster-Updated"
    status: DISABLED

- name: Delete a VZEN cluster
  zscaler.ziacloud.zia_vzen_cluster:
    provider: '{{ provider }}'
    id: 1254654
    state: absent
"""

RETURN = r"""
data:
  description: The VZEN cluster resource record.
  returned: on success
  type: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)

VZEN_TYPE_CHOICES = [
    "ANY",
    "NONE",
    "SME",
    "SMSM",
    "SMCA",
    "SMUI",
    "SMCDS",
    "SMDNSD",
    "SMAA",
    "SMTP",
    "SMQTN",
    "VIP",
    "UIZ",
    "UIAE",
    "SITEREVIEW",
    "PAC",
    "S_RELAY",
    "M_RELAY",
    "H_MON",
    "SMIKE",
    "NSS",
    "SMEZA",
    "SMLB",
    "SMFCCLT",
    "SMBA",
    "SMBAC",
    "SMESXI",
    "SMBAUI",
    "VZEN",
    "ZSCMCLT",
    "SMDLP",
    "ZSQUERY",
    "ADP",
    "SMCDSDLP",
    "SMSCIM",
    "ZSAPI",
    "ZSCMCDSSCLT",
    "LOCAL_MTS",
    "SVPN",
    "SMCASB",
    "SMFALCONUI",
    "MOBILEAPP_REG",
    "SMRESTSVR",
    "FALCONCA",
    "MOBILEAPP_NF",
    "ZIRSVR",
    "SMEDGEUI",
    "ALERTEVAL",
    "ALERTNOTIF",
    "SMPARTNERUI",
    "CQM",
    "DATAKEEPER",
    "SMBAM",
    "ZWACLT",
]

ATTRIBUTES = [
    "name",
    "status",
    "type",
    "ip_sec_enabled",
    "ip_address",
    "subnet_mask",
    "default_gateway",
    "virtual_zen_node_ids",
]


def _extract_node_ids(nodes):
    """Extract node IDs from virtual_zen_nodes (list of refs or dicts)."""
    if not nodes:
        return []
    out = []
    for n in nodes:
        if isinstance(n, dict) and "id" in n:
            out.append(n["id"])
        elif isinstance(n, (int, float)):
            out.append(int(n))
        elif hasattr(n, "as_dict"):
            d = n.as_dict()
            if "id" in d:
                out.append(d["id"])
    return sorted(out)


def _build_params(module):
    """Build params dict for SDK from module params."""
    params = {}
    for attr in ATTRIBUTES:
        val = module.params.get(attr)
        if val is not None:
            if attr == "virtual_zen_node_ids":
                params["virtual_zen_node_ids"] = val if isinstance(val, list) else []
            else:
                params[attr] = val
    return params


def _normalize_cluster(cluster):
    """Normalize cluster dict for idempotency comparison."""
    if not cluster:
        return {}
    norm = cluster.copy()
    norm.pop("id", None)
    norm.pop("last_modified_time", None)
    if "virtual_zen_nodes" in norm:
        norm["virtual_zen_node_ids"] = _extract_node_ids(norm.pop("virtual_zen_nodes"))
    return norm


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    cluster_id = module.params.get("id")
    cluster_name = module.params.get("name")
    params = _build_params(module)

    existing = None

    if cluster_id is not None:
        result, _unused, error = client.vzen_clusters.get_vzen_cluster(cluster_id)
        if error:
            module.fail_json(msg=f"Error fetching VZEN cluster with id {cluster_id}: {to_native(error)}")
        existing = result.as_dict()
    else:
        result, _unused, error = client.vzen_clusters.list_vzen_clusters()
        if error:
            module.fail_json(msg=f"Error listing VZEN clusters: {to_native(error)}")
        clusters_list = [c.as_dict() for c in result] if result else []
        if cluster_name:
            for c in clusters_list:
                if c.get("name") == cluster_name:
                    existing = c
                    break

    normalized_desired = _normalize_cluster(params)
    normalized_existing = _normalize_cluster(existing) if existing else {}
    differences_detected = False
    for key, desired_val in normalized_desired.items():
        existing_val = normalized_existing.get(key)
        if key == "virtual_zen_node_ids":
            existing_ids = _extract_node_ids(existing.get("virtual_zen_nodes")) if existing else []
            desired_ids = sorted(desired_val) if desired_val else []
            if sorted(existing_ids) != desired_ids:
                differences_detected = True
                break
        elif existing_val != desired_val:
            differences_detected = True
            break

    if module.check_mode:
        if state == "present" and (existing is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing:
            if differences_detected:
                id_to_update = existing.get("id")
                if not id_to_update:
                    module.fail_json(msg="Cannot update: ID is missing from the existing cluster.")
                merged = {
                    "name": existing.get("name"),
                    "status": existing.get("status"),
                    "type": existing.get("type"),
                    "ip_sec_enabled": existing.get("ip_sec_enabled"),
                    "ip_address": existing.get("ip_address"),
                    "subnet_mask": existing.get("subnet_mask"),
                    "default_gateway": existing.get("default_gateway"),
                    "virtual_zen_node_ids": _extract_node_ids(existing.get("virtual_zen_nodes")),
                }
                user_params = _build_params(module)
                for k, v in user_params.items():
                    if v is not None:
                        merged[k] = v
                update_params = merged
                updated, _unused, error = client.vzen_clusters.update_vzen_cluster(
                    id_to_update,
                    **update_params,
                )
                if error:
                    module.fail_json(msg=f"Error updating VZEN cluster: {to_native(error)}")
                module.exit_json(changed=True, data=updated.as_dict())
            else:
                module.exit_json(changed=False, data=existing)
        else:
            new_cluster, _unused, error = client.vzen_clusters.add_vzen_cluster(**params)
            if error:
                module.fail_json(msg=f"Error adding VZEN cluster: {to_native(error)}")
            module.exit_json(changed=True, data=new_cluster.as_dict())

    elif state == "absent":
        if existing:
            id_to_delete = existing.get("id")
            if not id_to_delete:
                module.fail_json(msg="Cannot delete: ID is missing from the existing cluster.")
            _unused, _unused, error = client.vzen_clusters.delete_vzen_cluster(id_to_delete)
            if error:
                module.fail_json(msg=f"Error deleting VZEN cluster: {to_native(error)}")
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
            name=dict(type="str", required=True),
            status=dict(
                type="str",
                required=False,
                choices=[
                    "ENABLED",
                    "DISABLED",
                    "DISABLED_BY_SERVICE_PROVIDER",
                    "NOT_PROVISIONED_IN_SERVICE_PROVIDER",
                ],
            ),
            type=dict(type="str", required=False, choices=VZEN_TYPE_CHOICES),
            ip_sec_enabled=dict(type="bool", required=False),
            ip_address=dict(type="str", required=False),
            subnet_mask=dict(type="str", required=False),
            default_gateway=dict(type="str", required=False),
            virtual_zen_node_ids=dict(type="list", elements="int", required=False),
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
