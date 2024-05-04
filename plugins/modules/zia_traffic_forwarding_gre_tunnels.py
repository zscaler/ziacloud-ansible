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
module: zia_traffic_forwarding_gre_tunnels
short_description: "GRE tunnel information"
description: "GRE tunnel information"
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description: "Unique identifier of the static IP address that is associated to a GRE tunnel"
    type: int
    required: false
  source_ip:
    description:
        - The source IP address of the GRE tunnel.
        - This is typically a static IP address in the organization or SD-WAN.
        - This IP address must be provisioned within the Zscaler service using the /staticIP endpoint.
    required: false
    type: str
  comment:
    description: Additional information about this GRE tunnel
    required: false
    type: str
  internal_ip_range:
    description: The start of the internal IP address in /29 CIDR range.
    required: false
    type: str
  within_country:
    description: Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address.
    required: false
    type: bool
  ip_unnumbered:
    description: This is required to support the automated SD-WAN provisioning of GRE tunnels, when set to true gre_tun_ip and gre_tun_id are set to null
    required: false
    type: bool
  sub_cloud:
    description: Restrict the data center virtual IP addresses (VIPs) only to those part of the subcloud
    required: false
    type: str
  primary_dest_vip_id:
    description: "The primary destination data center and virtual IP address (VIP) of the GRE tunnel"
    type: list
    elements: str
    required: false
  secondary_dest_vip_id:
    description: "The secondary destination data center and virtual IP address (VIP) of the GRE tunnel"
    type: list
    elements: str
    required: false
"""

EXAMPLES = r"""
- name: Create/Update/Delete GRE Numbered Tunnel.
  zscaler.ziacloud.zia_traffic_forwarding_gre_tunnels:
    provider: '{{ provider }}'
    source_ip: "1.1.1.1"
    comment: "Created with Ansible"
    ip_unnumbered: false
    within_country: false

- name: Create/Update/Delete GRE Unnumbered Tunnel.
  zscaler.ziacloud.zia_traffic_forwarding_gre_tunnels:
    provider: '{{ provider }}'
    source_ip: "1.1.1.1"
    comment: "Created with Ansible"
    ip_unnumbered: true
    within_country: true
    primary_dest_vip:
      - id:
        virtual_ip:
    secondary_dest_vip:
      - id:
        virtual_ip:
"""

RETURN = r"""
# The newly created static ip resource record.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_gre_tunnel(gre):
    """
    Normalize static ip data by setting computed values.
    """
    normalized = gre.copy()

    computed_values = [
        "id",
        "source_ip",
        "internal_ip_range",
        "within_country",
        "ip_unnumbered",
        "sub_cloud",
        "primary_dest_vip_id",
        "secondary_dest_vip_id",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    gre_tunnel = dict()
    params = [
        "id",
        "comment",
        "source_ip",
        "internal_ip_range",
        "within_country",
        "ip_unnumbered",
        "sub_cloud",
        # "primary_dest_vip_id",
        # "secondary_dest_vip_id",
    ]
    for param_name in params:
        gre_tunnel[param_name] = module.params.get(param_name, None)

    # Automatically set primary and secondary VIP IDs if not provided
    if not gre_tunnel.get("primary_dest_vip_id") or not gre_tunnel.get(
        "secondary_dest_vip_id"
    ):
        if gre_tunnel.get("source_ip"):
            closest_vips = client.traffic.get_closest_diverse_vip_ids(
                gre_tunnel["source_ip"]
            )
            gre_tunnel["primary_dest_vip_id"] = [closest_vips[0]]
            gre_tunnel["secondary_dest_vip_id"] = [closest_vips[1]]
        else:
            module.fail_json(msg="source_ip is required to determine closest VIPs.")

    # Check if ip_unnumbered is False and internal_ip_range is not set
    if gre_tunnel.get("ip_unnumbered") is False and not gre_tunnel.get(
        "internal_ip_range"
    ):
        # Fetch the first available IP range
        available_ranges = client.traffic.list_gre_ranges(limit=1).to_list()
        if available_ranges:
            first_range = available_ranges[0]
            gre_tunnel["internal_ip_range"] = (
                f"{first_range['start_ip_address']}-{first_range['end_ip_address']}"
            )
        else:
            module.fail_json(msg="No available IP ranges found.")

    tunnel_id = gre_tunnel.get("id", None)
    source_ip = gre_tunnel.get("source_ip", None)
    existing_gre_tunnel = None
    if tunnel_id is not None:
        existing_gre_tunnel = client.traffic.get_gre_tunnel(tunnel_id).to_dict()
    else:
        source_ips = client.traffic.list_gre_tunnels().to_list()
        if source_ip is not None:
            for ip in source_ips:
                if ip.get("source_ip", None) == source_ip:
                    existing_gre_tunnel = ip
                    break

    # Normalize and compare existing and desired data
    desired_gre = normalize_gre_tunnel(gre_tunnel)
    current_gre = (
        normalize_gre_tunnel(existing_gre_tunnel) if existing_gre_tunnel else {}
    )

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in desired_gre.items():
        if key not in fields_to_exclude and current_gre.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_gre.get(key)}, Desired: {value}"
            )

    if existing_gre_tunnel is not None:
        id = existing_gre_tunnel.get("id")
        existing_gre_tunnel.update(desired_gre)
        existing_gre_tunnel["id"] = id

    if state == "present":
        if existing_gre_tunnel is not None:
            if differences_detected:
                """Update"""
                update_gre = deleteNone(
                    {
                        "tunnel_id": id,
                        "source_ip": gre_tunnel.get("source_ip"),
                        "comment": gre_tunnel.get("comment"),
                        "internal_ip_range": gre_tunnel.get("internal_ip_range"),
                        "ip_unnumbered": gre_tunnel.get("ip_unnumbered"),
                        "within_country": gre_tunnel.get("within_country"),
                        "primary_dest_vip_id": (
                            gre_tunnel.get("primary_dest_vip_id")[0]
                            if gre_tunnel.get("primary_dest_vip_id")
                            else None
                        ),
                        "secondary_dest_vip_id": (
                            gre_tunnel.get("secondary_dest_vip_id")[0]
                            if gre_tunnel.get("secondary_dest_vip_id")
                            else None
                        ),
                        "sub_cloud": gre_tunnel.get("sub_cloud"),
                    }
                )
                updated_gre = client.traffic.update_gre_tunnel(**update_gre).to_dict()
                module.exit_json(changed=True, data=updated_gre)
            else:
                """No changes needed"""
                module.exit_json(
                    changed=False, data=existing_gre_tunnel, msg="No changes detected."
                )
        else:
            """Create"""
            create_tunnel = deleteNone(
                {
                    "source_ip": gre_tunnel.get("source_ip"),
                    "comment": gre_tunnel.get("comment"),
                    "internal_ip_range": gre_tunnel.get("internal_ip_range"),
                    "ip_unnumbered": gre_tunnel.get("ip_unnumbered"),
                    "within_country": gre_tunnel.get("within_country"),
                    "primary_dest_vip_id": (
                        gre_tunnel.get("primary_dest_vip_id")[0]
                        if gre_tunnel.get("primary_dest_vip_id")
                        else None
                    ),
                    "secondary_dest_vip_id": (
                        gre_tunnel.get("secondary_dest_vip_id")[0]
                        if gre_tunnel.get("secondary_dest_vip_id")
                        else None
                    ),
                    "sub_cloud": gre_tunnel.get("sub_cloud"),
                }
            )
            try:
                new_tunnel = client.traffic.add_gre_tunnel(**create_tunnel).to_dict()
                module.exit_json(changed=True, data=new_tunnel)
            except Exception as e:
                module.fail_json(msg=f"Failed to create GRE Tunnel: {str(e)}")
    elif (
        state == "absent"
        and existing_gre_tunnel is not None
        and existing_gre_tunnel.get("id") is not None
    ):
        code = client.traffic.delete_gre_tunnel(tunnel_id=id)
        if code > 299:
            module.exit_json(changed=False, data=None)
        module.exit_json(changed=True, data=existing_gre_tunnel)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        source_ip=dict(type="str", required=False),
        comment=dict(type="str", required=False),
        internal_ip_range=dict(type="str", required=False),
        within_country=dict(type="bool", required=False),
        ip_unnumbered=dict(type="bool", required=False),
        sub_cloud=dict(type="str", required=False),
        primary_dest_vip_id=dict(type="list", elements="str", required=False),
        secondary_dest_vip_id=dict(type="list", elements="str", required=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
