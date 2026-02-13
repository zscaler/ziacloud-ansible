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
module: zia_virtual_service_edge_node_info
short_description: "Gets information about Virtual Service Edge nodes"
description:
  - "Gets a list of Virtual Service Edge nodes or retrieves a specific node by ID or name."
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
  id:
    description:
      - The unique identifier for the Virtual Service Edge node.
      - System-generated Virtual Service Edge cluster ID.
    required: false
    type: int
  name:
    description:
      - Name of the Virtual Service Edge cluster.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all Virtual Service Edge nodes
  zscaler.ziacloud.zia_virtual_service_edge_node_info:
    provider: '{{ provider }}'

- name: Get a Virtual Service Edge node by ID
  zscaler.ziacloud.zia_virtual_service_edge_node_info:
    provider: '{{ provider }}'
    id: 123456

- name: Get a Virtual Service Edge node by name
  zscaler.ziacloud.zia_virtual_service_edge_node_info:
    provider: '{{ provider }}'
    name: "VZEN-Example-01"
"""

RETURN = r"""
nodes:
  description: A list of Virtual Service Edge nodes fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the Virtual Service Edge node (system-generated).
      returned: always
      type: int
      sample: 123456
    name:
      description: Name of the Virtual Service Edge cluster.
      returned: always
      type: str
      sample: "VZEN-Example-01"
    status:
      description:
        - Specifies the status of the Virtual Service Edge cluster.
        - The status is set to ENABLED by default.
      returned: always
      type: str
      sample: "ENABLED"
    type:
      description: The Virtual Service Edge cluster type.
      returned: always
      type: str
      sample: "SMLB"
    ip_sec_enabled:
      description:
        - A Boolean value that specifies whether to terminate IPSec traffic from the client
          at selected Virtual Service Edge instances for the Virtual Service Edge cluster.
      returned: always
      type: bool
    ip_address:
      description: The Virtual Service Edge cluster IP address.
      returned: always
      type: str
      sample: "10.0.0.100"
    subnet_mask:
      description: The Virtual Service Edge cluster subnet mask.
      returned: always
      type: str
      sample: "255.255.255.0"
    default_gateway:
      description: The IP address of the default gateway to the internet.
      returned: always
      type: str
      sample: "10.0.0.1"
    zgateway_id:
      description: The Zscaler service gateway ID.
      returned: when available
      type: int
    in_production:
      description: Represents the Virtual Service Edge instances deployed for production purposes.
      returned: always
      type: bool
    on_demand_support_tunnel_enabled:
      description: A Boolean value that indicates whether or not the On-Demand Support Tunnel is enabled.
      returned: always
      type: bool
    establish_support_tunnel_enabled:
      description: A Boolean value that indicates whether or not a support tunnel for Zscaler Support is enabled.
      returned: always
      type: bool
    load_balancer_ip_address:
      description:
        - The IP address of the load balancer.
        - This field is applicable only when the deployment_mode is set to CLUSTER.
      returned: when applicable
      type: str
    deployment_mode:
      description:
        - Specifies the deployment mode.
        - Select either STANDALONE or CLUSTER if you have the VMware ESXi platform.
      returned: always
      type: str
      sample: "STANDALONE"
    cluster_name:
      description: Virtual Service Edge cluster name.
      returned: when applicable
      type: str
    vzen_sku_type:
      description: The Virtual Service Edge SKU type. Supported values are SMALL, MEDIUM, LARGE.
      returned: when applicable
      type: str
      sample: "LARGE"
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    node_id = module.params.get("id")
    node_name = module.params.get("name")

    client = ZIAClientHelper(module)
    nodes = []

    if node_id is not None:
        node_obj, _unused, error = client.vzen_nodes.get_zen_node(node_id)
        if error or node_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve Virtual Service Edge node with ID '{node_id}': {to_native(error)}"
            )
        nodes = [node_obj.as_dict()]
    else:
        query_params = {}
        if node_name:
            query_params["search"] = node_name

        result, _unused, error = client.vzen_nodes.list_zen_nodes(
            query_params=query_params if query_params else None
        )
        if error:
            module.fail_json(
                msg=f"Error retrieving Virtual Service Edge nodes: {to_native(error)}"
            )

        node_list = [n.as_dict() for n in result] if result else []

        if node_name:
            matched = next(
                (n for n in node_list if n.get("name") == node_name), None
            )
            if not matched:
                available = [n.get("name") for n in node_list]
                module.fail_json(
                    msg=f"Virtual Service Edge node with name '{node_name}' not found. Available nodes: {available}"
                )
            nodes = [matched]
        else:
            nodes = node_list

    module.exit_json(changed=False, nodes=nodes)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
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
