#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Technology Alliances, <zscaler-partner-labs@z-bd.com>

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
module: zia_traffic_forwarding_gre_tunnel_facts
short_description: "Gets the GRE tunnel information for the specified ID.D"
description: "Gets the GRE tunnel information for the specified ID."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider

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
    required: true
    type: str
"""

EXAMPLES = r"""
- name: Retrieve Details of All GRE Tunnels.
  zscaler.ziacloud.zia_traffic_forwarding_gre_tunnel_facts:
    provider: '{{ provider }}'

- name: Retrieve Details of Specific GRE Tunnel By Source IP Address.
  zscaler.ziacloud.zia_traffic_forwarding_gre_tunnel_facts:
    provider: '{{ provider }}'
    ip_address: 1.1.1.1

- name: Retrieve Details of Specific GRE Tunnel By ID.
  zscaler.ziacloud.zia_traffic_forwarding_gre_tunnel_facts:
    provider: '{{ provider }}'
    id: 82709

"""

RETURN = r"""
# Returns information on GRE Tunnel.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    tunnel_id = module.params.get("id", None)
    source_ip = module.params.get("source_ip", None)
    client = ZIAClientHelper(module)
    gre_tunnels = []
    if tunnel_id is not None:
        gre_tunnel = client.traffic.get_gre_tunnel(tunnel_id).to_dict()
        gre_tunnels = [gre_tunnel]
    else:
        all_gre_tunnels = client.traffic.list_gre_tunnels().to_list()
        if source_ip is not None:
            gre_tunnel = next(
                (
                    gre
                    for gre in all_gre_tunnels
                    if gre.get("source_ip", None) == source_ip
                ),
                None,
            )
            if gre_tunnel is None:
                module.fail_json(
                    msg=f"Failed to retrieve GRE tunnel with source IP address: '{source_ip}'"
                )
            gre_tunnels = [gre_tunnel]
        else:
            gre_tunnels = all_gre_tunnels

    module.exit_json(changed=False, data=gre_tunnels)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        source_ip=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
