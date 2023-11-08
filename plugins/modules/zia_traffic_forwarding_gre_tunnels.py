#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, William Guilherme <wguilherme@securitygeek.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_traffic_forwarding_gre_tunnels
short_description: "GRE tunnel information"
description:
  - "GRE tunnel information"
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
options:
  username:
    description: "Username of admin user that is provisioned"
    required: true
    type: str
  password:
    description: "Password of the admin user"
    required: true
    type: str
  api_key:
    description: "The obfuscated form of the API key"
    required: true
    type: str
  base_url:
    description: "The host and basePath for the cloud services API"
    required: true
    type: str
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
  primary_dest_vip:
    description:
      - The primary destination data center and virtual IP address (VIP) of the GRE tunnel.
    required: false
    type: list
    elements: dict
    suboptions:
        id:
            description: "Unique identifer of the GRE virtual IP address (VIP)"
            type: int
            required: false
        virtual_ip:
            description: "GRE cluster virtual IP address (VIP)"
            type: str
            required: true
  secondary_dest_vip:
    description:
      - The secondary destination data center and virtual IP address (VIP) of the GRE tunnel.
    required: false
    type: list
    elements: dict
    suboptions:
        id:
            description: "Unique identifer of the GRE virtual IP address (VIP)"
            type: int
            required: false
        virtual_ip:
            description: "GRE cluster virtual IP address (VIP)"
            type: str
            required: true
  internal_ip_range:
    description:
        - The start of the internal IP address in /29 CIDR range
    required: false
    type: str
  within_country:
    description:
        - Restrict the data center virtual IP addresses (VIPs) only to those within the same country as the source IP address
    required: false
    type: bool
  comment:
    description:
        - Additional information about this GRE tunnel
    required: false
    type: str
  ip_unnumbered:
    description:
        - This is required to support the automated SD-WAN provisioning of GRE tunnels
        - When set to true gre_tun_ip and gre_tun_id are set to null
    required: false
    type: bool
  subcloud:
    description:
        - Restrict the data center virtual IP addresses (VIPs) only to those part of the subcloud
    required: false
    type: str
"""

EXAMPLES = """

- name: Gather Information Details of a ZIA GRE Tunnels
  zscaler.ziacloud.zia_traffic_forwarding_gre_tunnels:
    comment: "Toronto_GRE_Tunnel01"
    source_ip: "Toronto_GRE_Tunnel01"
    within_country: true
    ip_unnumbered: true
    primary_dest_vip:
        id:
        virtual_ip:
    secondary_dest_vip:
        id:
        virtual_ip:
"""

RETURN = """
# Returns information on a specified ZIA Admin User.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    zia_argument_spec,
)
from zscaler import ZIA


def core(module):
    state = module.params.get("state", None)
    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )
    gre_tunnels = dict()
    params = [
        "id",
        "comment",
        "source_ip",
        "primary_dest_vip",
        "secondary_dest_vip",
        "internal_ip_range",
        "within_country",
        "ip_unnumbered",
        "subcloud",
    ]
    for param_name in params:
        gre_tunnels[param_name] = module.params.get(param_name, None)
    existing_gre_tunnels = service.getByIDOrName(
        gre_tunnels.get("id"), gre_tunnels.get("name")
    )
    if existing_gre_tunnels is not None:
        id = existing_gre_tunnels.get("id")
        existing_gre_tunnels.update(gre_tunnels)
        existing_gre_tunnels["id"] = id
    if state == "present":
        if existing_gre_tunnels is not None:
            """Update"""
            service.update(existing_gre_tunnels)
            module.exit_json(changed=True, data=existing_gre_tunnels)
        else:
            """Create"""
            gre_tunnels = service.create(gre_tunnels)
            module.exit_json(changed=False, data=gre_tunnels)
    elif state == "absent":
        if existing_gre_tunnels is not None:
            service.delete(existing_gre_tunnels.get("id"))
            module.exit_json(changed=False, data=existing_gre_tunnels)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int"),
        comment=dict(type="str", required=False),
        source_ip=dict(type="str", required=True),
        internal_ip_range=dict(type="str", required=False),
        ip_unnumbered=dict(type="bool", required=False),
        within_country=dict(type="bool", required=False),
        subcloud=dict(type="str", required=False),
        primary_dest_vip=dict(
            type="list",
            elements="dict",
            options=dict(
                id=dict(type="int"),
                virtual_ip=dict(type="str", required=False),
            ),
            required=False,
        ),
        secondary_dest_vip=dict(
            type="list",
            elements="dict",
            options=dict(
                id=dict(type="int"),
                virtual_ip=dict(type="str", required=False),
            ),
            required=False,
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
