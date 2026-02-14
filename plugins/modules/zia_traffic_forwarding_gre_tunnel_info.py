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
module: zia_traffic_forwarding_gre_tunnel_info
short_description: "Gets the GRE tunnel information for the specified ID"
description: "Gets the GRE tunnel information for the specified ID."
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
    description: "Unique identifier of the static IP address that is associated to a GRE tunnel"
    required: false
    type: int
  source_ip:
    description:
      - The source IP address of the GRE tunnel.
      - This is typically a static IP address in the organization or SD-WAN.
      - This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Retrieve Details of All GRE Tunnels.
  zscaler.ziacloud.zia_traffic_forwarding_gre_tunnel_info:
    provider: '{{ provider }}'

- name: Retrieve Details of Specific GRE Tunnel By Source IP Address.
  zscaler.ziacloud.zia_traffic_forwarding_gre_tunnel_info:
    provider: '{{ provider }}'
    source_ip: 1.1.1.1

- name: Retrieve Details of Specific GRE Tunnel By ID.
  zscaler.ziacloud.zia_traffic_forwarding_gre_tunnel_info:
    provider: '{{ provider }}'
    id: 82709
"""

RETURN = r"""
gre_tunnels:
  description: A list of GRE tunnel configurations retrieved from the ZIA platform.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the GRE tunnel.
      returned: always
      type: int
      sample: 3687136
    comment:
      description: User-provided comments about the GRE tunnel.
      returned: always
      type: str
      sample: "GRE Tunnel Example"
    internal_ip_range:
      description: Internal IP range configured for the GRE tunnel.
      returned: always
      type: str
      sample: "172.19.48.72"
    ip_unnumbered:
      description: Flag indicating if the tunnel uses unnumbered IP.
      returned: always
      type: bool
      sample: false
    source_ip:
      description: The source IP address used by the GRE tunnel.
      returned: always
      type: str
      sample: "1.1.1.1"
    last_modification_time:
      description: Unix timestamp of when the GRE tunnel configuration was last modified.
      returned: always
      type: int
      sample: 1721348656
    last_modified_by:
      description: Details of the user who last modified the GRE tunnel configuration.
      returned: always
      type: dict
      contains:
        id:
          description: Unique identifier of the user.
          returned: always
          type: int
          sample: 44772836
        name:
          description: Name of the user.
          returned: always
          type: str
          sample: "DEFAULT ADMIN"
    primary_dest_vip:
      description: Primary destination virtual IP configuration for the GRE tunnel.
      returned: always
      type: dict
      contains:
        id:
          description: Unique identifier of the primary destination.
          returned: always
          type: int
          sample: 79439
        virtual_ip:
          description: Virtual IP address of the primary destination.
          returned: always
          type: str
          sample: "147.161.128.23"
        city:
          description: City of the primary destination.
          returned: always
          type: str
          sample: "Sao Paulo"
        country_code:
          description: Country code of the primary destination.
          returned: always
          type: str
          sample: "US"
        datacenter:
          description: Datacenter where the primary VIP is located.
          returned: always
          type: str
          sample: "SAO4"
        latitude:
          description: Latitude of the primary destination.
          returned: always
          type: float
          sample: -22.0
        longitude:
          description: Longitude of the primary destination.
          returned: always
          type: float
          sample: -47.0
    secondary_dest_vip:
      description: Secondary destination virtual IP configuration for the GRE tunnel.
      returned: always
      type: dict
      contains:
        id:
          description: Unique identifier of the secondary destination.
          returned: always
          type: int
          sample: 205298
        virtual_ip:
          description: Virtual IP address of the secondary destination.
          returned: always
          type: str
          sample: "170.85.16.65"
        city:
          description: City of the secondary destination.
          returned: always
          type: str
          sample: "Rio de Janeiro"
        country_code:
          description: Country code of the secondary destination.
          returned: always
          type: str
          sample: "BR"
        datacenter:
          description: Datacenter where the secondary VIP is located.
          returned: always
          type: str
          sample: "RIO1"
        latitude:
          description: Latitude of the secondary destination.
          returned: always
          type: float
          sample: -23.0
        longitude:
          description: Longitude of the secondary destination.
          returned: always
          type: float
          sample: -43.0
"""


from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    collect_all_items,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    tunnel_id = module.params.get("id")
    source_ip = module.params.get("source_ip")

    client = ZIAClientHelper(module)
    gre_tunnels = []

    if tunnel_id is not None:
        tunnel_obj, _unused, error = client.gre_tunnel.get_gre_tunnel(tunnel_id)
        if error or tunnel_obj is None:
            module.fail_json(msg=f"Failed to retrieve GRE tunnel with ID '{tunnel_id}': {to_native(error)}")
        gre_tunnels = [tunnel_obj.as_dict()]
    else:
        result, err = collect_all_items(client.gre_tunnel.list_gre_tunnels)
        if err:
            module.fail_json(msg=f"Error retrieving GRE tunnels: {to_native(err)}")

        tunnel_list = [t.as_dict() if hasattr(t, "as_dict") else t for t in result] if result else []

        if source_ip:
            matched = next((t for t in tunnel_list if t.get("source_ip") == source_ip), None)
            if not matched:
                available = [t.get("source_ip") for t in tunnel_list]
                module.fail_json(msg=f"GRE tunnel with source IP '{source_ip}' not found. Available: {available}")
            gre_tunnels = [matched]
        else:
            gre_tunnels = tunnel_list

    module.exit_json(changed=False, gre_tunnels=gre_tunnels)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        source_ip=dict(type="str", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["id", "source_ip"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
