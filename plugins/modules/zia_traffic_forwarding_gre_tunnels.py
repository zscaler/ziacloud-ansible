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
notes:
    - Check mode is supported.
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
  primary_dest_vip:
    description: "The primary destination data center and virtual IP address (VIP) of the GRE tunnel"
    type: list
    elements: str
    required: false
  secondary_dest_vip:
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
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import deleteNone
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper


def normalize_gre_tunnel(gre):
    """
    Normalize GRE tunnel data by removing computed-only attributes.
    """
    normalized = gre.copy()
    computed_values = [
        "id",
        "source_ip",
        "internal_ip_range",
        "within_country",
        "ip_unnumbered",
        "sub_cloud",
        "primary_dest_vip",
        "secondary_dest_vip",
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
        "primary_dest_vip",
        "secondary_dest_vip",
    ]
    for param_name in params:
        gre_tunnel[param_name] = module.params.get(param_name, None)

    if "sourceIp" in gre_tunnel and "source_ip" not in gre_tunnel:
        gre_tunnel["source_ip"] = gre_tunnel.pop("sourceIp")

    # Handle fallback IP range logic
    if gre_tunnel.get("ip_unnumbered") is False and not gre_tunnel.get("internal_ip_range"):
        available_ranges, _, error = client.gre_tunnel.list_gre_ranges(query_params={"limit": 1})
        if error:
            module.fail_json(msg=f"Error fetching GRE ranges: {to_native(error)}")
        if available_ranges:
            first_range = available_ranges[0]
            start_ip = first_range.get("start_ip_address") or first_range.get("startIpAddress") or first_range.get("startIPAddress")
            end_ip = first_range.get("end_ip_address") or first_range.get("endIpAddress") or first_range.get("endIPAddress")
            if not start_ip or not end_ip:
                module.fail_json(msg="Missing expected IP fields (start/end IP) in GRE range response.")

            gre_tunnel["internal_ip_range"] = f"{start_ip}-{end_ip}"

    tunnel_id = gre_tunnel.get("id")
    source_ip = gre_tunnel.get("source_ip")
    existing_gre_tunnel = None

    if tunnel_id:
        result, _, error = client.gre_tunnel.get_gre_tunnel(tunnel_id)
        if error:
            module.fail_json(msg=f"Failed to fetch GRE tunnel: {to_native(error)}")
        if result:
            existing_gre_tunnel = result.as_dict()
    else:
        tunnels, _, error = client.gre_tunnel.list_gre_tunnels()
        if error:
            module.fail_json(msg=f"Error listing GRE tunnels: {to_native(error)}")
        for tunnel in tunnels or []:
            tunnel_dict = tunnel.as_dict() if hasattr(tunnel, "as_dict") else tunnel
            if tunnel_dict.get("source_ip") == source_ip:
                existing_gre_tunnel = tunnel_dict
                break

    desired_gre = normalize_gre_tunnel(gre_tunnel)
    current_gre = normalize_gre_tunnel(existing_gre_tunnel) if existing_gre_tunnel else {}

    differences_detected = any(
        current_gre.get(k) != desired_gre.get(k)
        for k in desired_gre if k != "id"
    )

    if module.check_mode:
        if state == "present" and (existing_gre_tunnel is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_gre_tunnel:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if existing_gre_tunnel:
        existing_gre_tunnel.update(desired_gre)
        existing_gre_tunnel["id"] = tunnel_id

    if state == "present":
        if existing_gre_tunnel:
            if differences_detected:
                update_gre = deleteNone(
                    {
                        "tunnel_id": tunnel_id,
                        "source_ip": gre_tunnel.get("source_ip"),
                        "comment": gre_tunnel.get("comment"),
                        "internal_ip_range": gre_tunnel.get("internal_ip_range"),
                        "ip_unnumbered": gre_tunnel.get("ip_unnumbered"),
                        "within_country": gre_tunnel.get("within_country"),
                        "primary_dest_vip": gre_tunnel.get("primary_dest_vip"),
                        "secondary_dest_vip": gre_tunnel.get("secondary_dest_vip"),
                        "sub_cloud": gre_tunnel.get("sub_cloud"),
                    }
                )
                # if "source_ip" in update_gre:
                #     update_gre["sourceIp"] = update_gre.pop("source_ip")

                # if "internal_ip_range" in update_gre:
                #     update_gre["internalIPRange"] = update_gre.pop("internal_ip_range")

                result, _, error = client.gre_tunnel.update_gre_tunnel(**update_gre)
                if error or not result:
                    module.fail_json(msg=f"Failed to update GRE tunnel: {to_native(error)}")
                module.exit_json(changed=True, data=result.as_dict())
            else:
                module.exit_json(changed=False, data=existing_gre_tunnel, msg="No changes detected.")
        else:
            create_tunnel = deleteNone(
                {
                    "source_ip": gre_tunnel.get("source_ip"),
                    "comment": gre_tunnel.get("comment"),
                    "internal_ip_range": gre_tunnel.get("internal_ip_range"),
                    "ip_unnumbered": gre_tunnel.get("ip_unnumbered"),
                    "within_country": gre_tunnel.get("within_country"),
                    "primary_dest_vip": gre_tunnel.get("primary_dest_vip"),
                    "secondary_dest_vip": gre_tunnel.get("secondary_dest_vip"),
                    "sub_cloud": gre_tunnel.get("sub_cloud"),
                }
            )
            # if "source_ip" in create_tunnel:
            #     create_tunnel["sourceIp"] = create_tunnel.pop("source_ip")

            # if "internal_ip_range" in create_tunnel:
            #     create_tunnel["internalIPRange"] = create_tunnel.pop("internal_ip_range")

            module.warn(f"gre_tunnel keys: {gre_tunnel.keys()}")
            module.warn(f"gre_tunnel source_ip: {gre_tunnel.get('source_ip')}")
            result, _, error = client.gre_tunnel.add_gre_tunnel(**create_tunnel)
            module.warn(f"create_tunnel payload: {create_tunnel}")
            if error or not result:
                module.fail_json(msg=f"Failed to create GRE tunnel: {to_native(error)}")
            module.exit_json(changed=True, data=result.as_dict())

    elif state == "absent" and existing_gre_tunnel and tunnel_id:
        _, _, error = client.gre_tunnel.delete_gre_tunnel(tunnel_id=tunnel_id)
        if error:
            module.fail_json(msg=f"Failed to delete GRE tunnel: {to_native(error)}")
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
        primary_dest_vip=dict(
            type="dict",
            required=False,
            options=dict(
                id=dict(type="str", required=False),
                virtual_ip=dict(type="str", required=False),
            ),
        ),
        secondary_dest_vip=dict(
            type="dict",
            required=False,
            options=dict(
                id=dict(type="str", required=False),
                virtual_ip=dict(type="str", required=False),
            ),
        ),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
