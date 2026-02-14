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
module: zia_virtual_service_edge_node
short_description: "Adds a virtual service edge node."
description:
  - "Adds a virtual service edge node."
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
    description:
      - The unique identifier for the Virtual Service Edge node.
      - Used to reference an existing node for update or delete operations.
    required: false
    type: int
  name:
    description:
      - Name of the Virtual Service Edge node.
    required: true
    type: str
  status:
    description:
      - Specifies the status of the Virtual Service Edge cluster.
      - The status is set to ENABLED by default.
    required: false
    type: str
    choices:
      - ENABLED
      - DISABLED
      - DISABLED_BY_SERVICE_PROVIDER
      - NOT_PROVISIONED_IN_SERVICE_PROVIDER
      - IN_TRIAL
  type:
    description:
      - The Virtual Service Edge cluster type.
      - For the complete list of supported types refer to the API documentation.
      - U(https://help.zscaler.com/zia/service-edges#/virtualZenNodes-post)
    required: false
    type: str
  ip_sec_enabled:
    description:
      - A Boolean value that specifies whether to terminate IPSec traffic from the client
        at selected Virtual Service Edge instances for the Virtual Service Edge cluster.
    required: false
    type: bool
  ip_address:
    description:
      - The Virtual Service Edge cluster IP address.
      - Only IPv4 addresses are supported.
    required: false
    type: str
  subnet_mask:
    description:
      - The Virtual Service Edge cluster subnet mask (e.g. 255.255.255.0).
      - Only IPv4 addresses are supported.
    required: false
    type: str
  default_gateway:
    description:
      - The IP address of the default gateway to the internet.
      - Only IPv4 addresses are supported.
    required: false
    type: str
  in_production:
    description:
      - Represents the Virtual Service Edge instances deployed for production purposes.
    required: false
    type: bool
  on_demand_support_tunnel_enabled:
    description:
      - A Boolean value that indicates whether or not the On-Demand Support Tunnel is enabled.
    required: false
    type: bool
  establish_support_tunnel_enabled:
    description:
      - A Boolean value that indicates whether or not a support tunnel for Zscaler Support is enabled.
    required: false
    type: bool
  load_balancer_ip_address:
    description:
      - The IP address of the load balancer.
      - This field is applicable only when the deployment_mode is set to C(CLUSTER).
    required: false
    type: str
  deployment_mode:
    description:
      - Specifies the deployment mode.
      - Select either C(STANDALONE) or C(CLUSTER) if you have the VMware ESXi platform.
      - Otherwise, select only C(STANDALONE).
    required: false
    type: str
    choices:
      - STANDALONE
      - CLUSTER
  cluster_name:
    description:
      - Virtual Service Edge cluster name.
    required: false
    type: str
  vzen_sku_type:
    description:
      - The Virtual Service Edge SKU type.
    required: false
    type: str
    choices:
      - SMALL
      - MEDIUM
      - LARGE
"""

EXAMPLES = r"""
- name: Create a Virtual Service Edge node with basic configuration
  zscaler.ziacloud.zia_virtual_service_edge_node:
    provider: '{{ provider }}'
    name: "VZEN-Example-01"
    status: ENABLED
    ip_address: "10.0.0.100"
    subnet_mask: "255.255.255.0"
    default_gateway: "10.0.0.1"
    type: "SMLB"
    deployment_mode: STANDALONE

- name: Create a Virtual Service Edge node with cluster deployment
  zscaler.ziacloud.zia_virtual_service_edge_node:
    provider: '{{ provider }}'
    status: ENABLED
    ip_address: "10.0.0.100"
    subnet_mask: "255.255.255.0"
    default_gateway: "10.0.0.1"
    type: "VZEN"
    deployment_mode: CLUSTER
    load_balancer_ip_address: "10.0.0.50"
    vzen_sku_type: LARGE
    ip_sec_enabled: false

- name: Update an existing Virtual Service Edge node by ID
  zscaler.ziacloud.zia_virtual_service_edge_node:
    provider: '{{ provider }}'
    id: 123456
    name: "VZEN-Updated"
    status: DISABLED

- name: Delete a Virtual Service Edge node
  zscaler.ziacloud.zia_virtual_service_edge_node:
    provider: '{{ provider }}'
    id: 123456
    state: absent
"""

RETURN = r"""
data:
  description: The Virtual Service Edge node resource record.
  returned: on success
  type: dict
  contains:
    id:
      description: The unique identifier for the Virtual Service Edge node.
      type: int
    name:
      description: Name of the Virtual Service Edge node.
      type: str
    status:
      description: The status of the Virtual Service Edge cluster.
      type: str
    type:
      description: The Virtual Service Edge cluster type.
      type: str
    ip_address:
      description: The Virtual Service Edge cluster IP address.
      type: str
    subnet_mask:
      description: The Virtual Service Edge cluster subnet mask.
      type: str
    default_gateway:
      description: The default gateway IP address.
      type: str
    ip_sec_enabled:
      description: Whether IPSec traffic termination is enabled.
      type: bool
    in_production:
      description: Whether the node is deployed for production.
      type: bool
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


VZEN_NODE_ATTRIBUTES = [
    "name",
    "status",
    "type",
    "ip_address",
    "subnet_mask",
    "default_gateway",
    "ip_sec_enabled",
    "in_production",
    "on_demand_support_tunnel_enabled",
    "establish_support_tunnel_enabled",
    "load_balancer_ip_address",
    "deployment_mode",
    "cluster_name",
    "vzen_sku_type",
]


def normalize_vzen_node(node):
    """
    Remove computed attributes from a vzen node dict to make comparison easier.
    """
    if not node:
        return {}
    normalized = node.copy()
    computed_values = ["id", "zgateway_id", "zgatewayId"]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    node_id = module.params.get("id")
    node_name = module.params.get("name")

    vzen_node_params = {
        p: module.params.get(p)
        for p in VZEN_NODE_ATTRIBUTES
        if module.params.get(p) is not None
    }

    existing_node = None

    if node_id:
        result, _unused, error = client.vzen_nodes.get_zen_node(node_id)
        if error:
            module.fail_json(
                msg=f"Error fetching Virtual Service Edge node with id {node_id}: {to_native(error)}"
            )
        existing_node = result.as_dict()
    else:
        result, _unused, error = client.vzen_nodes.list_zen_nodes(
            query_params={"search": node_name} if node_name else None
        )
        if error:
            module.fail_json(
                msg=f"Error listing Virtual Service Edge nodes: {to_native(error)}"
            )
        nodes_list = [node.as_dict() for node in result]
        if node_name:
            for node in nodes_list:
                if node.get("name") == node_name:
                    existing_node = node
                    break

    normalized_desired = normalize_vzen_node(vzen_node_params)
    normalized_existing = normalize_vzen_node(existing_node) if existing_node else {}

    differences_detected = False
    for key, value in normalized_desired.items():
        if normalized_existing.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing.get(key)}, Desired: {value}"
            )

    if module.check_mode:
        if state == "present" and (existing_node is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_node:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_node:
            if differences_detected:
                node_id_to_update = existing_node.get("id")
                if not node_id_to_update:
                    module.fail_json(
                        msg="Cannot update Virtual Service Edge node: ID is missing from the existing resource."
                    )

                updated_node, _unused, error = client.vzen_nodes.update_zen_node(
                    node_id_to_update,
                    **vzen_node_params,
                )
                if error:
                    module.fail_json(
                        msg=f"Error updating Virtual Service Edge node: {to_native(error)}"
                    )
                module.exit_json(changed=True, data=updated_node.as_dict())
            else:
                module.exit_json(changed=False, data=existing_node)
        else:
            new_node, _unused, error = client.vzen_nodes.add_zen_node(**vzen_node_params)
            if error:
                module.fail_json(
                    msg=f"Error adding Virtual Service Edge node: {to_native(error)}"
                )
            module.exit_json(changed=True, data=new_node.as_dict())

    elif state == "absent":
        if existing_node:
            node_id_to_delete = existing_node.get("id")
            if not node_id_to_delete:
                module.fail_json(
                    msg="Cannot delete Virtual Service Edge node: ID is missing from the existing resource."
                )

            _unused, _unused, error = client.vzen_nodes.delete_zen_node(
                node_id_to_delete
            )
            if error:
                module.fail_json(
                    msg=f"Error deleting Virtual Service Edge node: {to_native(error)}"
                )
            module.exit_json(changed=True, data=existing_node)
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
                    "IN_TRIAL",
                ],
            ),
            type=dict(type="str", required=False),
            ip_sec_enabled=dict(type="bool", required=False),
            ip_address=dict(type="str", required=False),
            subnet_mask=dict(type="str", required=False),
            default_gateway=dict(type="str", required=False),
            in_production=dict(type="bool", required=False),
            on_demand_support_tunnel_enabled=dict(type="bool", required=False),
            establish_support_tunnel_enabled=dict(type="bool", required=False),
            load_balancer_ip_address=dict(type="str", required=False),
            deployment_mode=dict(
                type="str",
                required=False,
                choices=["STANDALONE", "CLUSTER"],
            ),
            cluster_name=dict(type="str", required=False),
            vzen_sku_type=dict(
                type="str",
                required=False,
                choices=["SMALL", "MEDIUM", "LARGE"],
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
