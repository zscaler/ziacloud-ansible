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
module: zia_vzen_cluster_info
short_description: "Gets information about Virtual Service Edge clusters"
description:
  - "Gets Virtual Service Edge (VZEN) cluster configurations."
  - "Retrieves a specific cluster by ID or name."
  - "If neither id nor name is provided, lists all clusters."
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
- name: Get all Virtual Service Edge clusters
  zscaler.ziacloud.zia_vzen_cluster_info:
    provider: '{{ provider }}'

- name: Get a VZEN cluster by ID
  zscaler.ziacloud.zia_vzen_cluster_info:
    provider: '{{ provider }}'
    id: 1254654

- name: Get a VZEN cluster by name
  zscaler.ziacloud.zia_vzen_cluster_info:
    provider: '{{ provider }}'
    name: "VZEN-Cluster-01"
"""

RETURN = r"""
clusters:
  description: A list of Virtual Service Edge clusters fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: System-generated Virtual Service Edge cluster ID.
      returned: always
      type: int
    name:
      description: Name of the Virtual Service Edge cluster.
      returned: always
      type: str
    status:
      description: Status of the cluster (e.g., ENABLED, DISABLED).
      returned: when available
      type: str
    type:
      description: The Virtual Service Edge cluster type.
      returned: when available
      type: str
    ip_sec_enabled:
      description: Whether IPSec traffic is terminated at selected instances.
      returned: when available
      type: bool
    ip_address:
      description: The cluster IP address.
      returned: when available
      type: str
    subnet_mask:
      description: The cluster subnet mask.
      returned: when available
      type: str
    default_gateway:
      description: The IP address of the default gateway.
      returned: when available
      type: str
    virtual_zen_nodes:
      description: Virtual Service Edge instances in the cluster.
      returned: when available
      type: list
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    cluster_id = module.params.get("id")
    cluster_name = module.params.get("name")

    client = ZIAClientHelper(module)

    if cluster_id is not None:
        result, _unused, error = client.vzen_clusters.get_vzen_cluster(cluster_id)
        if error:
            module.fail_json(msg=f"Failed to retrieve VZEN cluster with ID '{cluster_id}': {to_native(error)}")
        clusters_out = [result.as_dict()]
    else:
        query_params = {}
        if cluster_name:
            query_params["search"] = cluster_name
        result, _unused, error = client.vzen_clusters.list_vzen_clusters(query_params=query_params if query_params else None)
        if error:
            module.fail_json(msg=f"Error retrieving VZEN clusters: {to_native(error)}")
        clusters_list = [c.as_dict() for c in result] if result else []

        if cluster_name:
            matched = next(
                (c for c in clusters_list if c.get("name") == cluster_name),
                None,
            )
            if matched is None:
                module.fail_json(msg=f"VZEN cluster with name '{cluster_name}' not found.")
            clusters_out = [matched]
        else:
            clusters_out = clusters_list

    module.exit_json(changed=False, clusters=clusters_out)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
