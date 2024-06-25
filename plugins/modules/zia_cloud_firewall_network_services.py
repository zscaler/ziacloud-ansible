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
module: zia_cloud_firewall_network_services
short_description: "Adds a new network service."
description: "Adds a new network service."
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
    description: "The unique identifier for the network service"
    required: false
    type: int
  name:
    description: "The name for the application layer service"
    required: true
    type: str
  description:
    description:
      - The description for the application layer service
      - The description cannot exceed 10240 characters.
    required: false
    type: str
  type:
    description: "The service indicates that this is an admin-defined service."
    required: false
    type: str
    choices:
        - CUSTOM
    default: CUSTOM
  tag:
    description: "The network service tag"
    required: false
    type: list
    elements: str
    choices:
      - ICMP_ANY
      - UDP_ANY
      - TCP_ANY
      - OTHER_NETWORK_SERVICE
      - DNS
      - NETBIOS
      - FTP
      - GNUTELLA
      - H_323
      - HTTP
      - HTTPS
      - IKE
      - IMAP
      - ILS
      - IKE_NAT
      - IRC
      - LDAP
      - QUIC
      - TDS
      - NETMEETING
      - NFS
      - NTP
      - SIP
      - SNMP
      - SMB
      - SMTP
      - SSH
      - SYSLOG
      - TELNET
      - TRACEROUTE
      - POP3
      - PPTP
      - RADIUS
      - REAL_MEDIA
      - RTSP
      - VNC
      - WHOIS
      - KERBEROS_SEC
      - TACACS
      - SNMPTRAP
      - NMAP
      - RSYNC
      - L2TP
      - HTTP_PROXY
      - PC_ANYWHERE
      - MSN
      - ECHO
      - AIM
      - IDENT
      - YMSG
      - SCCP
      - MGCP_UA
      - MGCP_CA
      - VDO_LIVE
      - OPENVPN
      - TFTP
      - FTPS_IMPLICIT
      - ZSCALER_PROXY_NW_SERVICES
      - GRE_PROTOCOL
      - ESP_PROTOCOL
      - DHCP
  src_tcp_ports:
    type: list
    elements: dict
    description:
      - List of tcp port range pairs, e.g. [35000, 35000] for port 35000.
      - The TCP source port number example 50 or port number range if any, that is used by the network service.
    required: false
    suboptions:
      start:
        type: int
        required: false
        description:
          - List of valid source TCP ports.
          - Start and End cannot be the same value.
      end:
        type: int
        required: false
        description:
          - List of valid source TCP ports.
  dest_tcp_ports:
    type: list
    elements: dict
    description:
      - The TCP source port number example 50 or port number range if any, that is used by the network service.
    required: false
    suboptions:
      start:
        type: int
        required: false
        description:
          - List of valid destination TCP ports.
      end:
        type: int
        required: false
        description:
          - List of valid destination TCP ports.
  src_udp_ports:
    type: list
    elements: dict
    description:
      - List of udp port range pairs, e.g. [35000, 35000] for port 35000.
      - The list of UDP source port number example 50 or port number range if any, that is used by the network service.
    required: false
    suboptions:
      start:
        type: int
        required: false
        description:
          - List of valid source UDP ports.
      end:
        type: int
        required: false
        description:
          - List of valid source UDP ports.
  dest_udp_ports:
    type: list
    elements: dict
    description:
      - List of udp port range pairs, e.g. [35000, 35000] for port 35000.
      - The UDP destination port number example 50 or port number range if any, that is used by the network service.
    required: false
    suboptions:
      start:
        type: int
        required: false
        description:
          - List of valid destination UDP ports.
      end:
        type: int
        required: false
        description:
          - List of valid destination UDP ports.
"""

EXAMPLES = r"""

- name: Create/Update/Delete Network Services.
  zscaler.ziacloud.zia_cloud_firewall_network_services:
    provider: '{{ provider }}'
    name: "example"
    description: "example"
    src_tcp_ports:
      - start: 5002
        end: 5005
    dest_tcp_ports:
      - start: 5003
        end: 5005
    type: "CUSTOM"
"""

RETURN = r"""
# The newly created network services resource record.
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


def normalize_service(service):
    """
    Normalize network service data by setting computed values.
    """
    normalized = service.copy()

    computed_values = [
        "creatorContext",
        "isNameL10nTag",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    network_service = dict()
    params = [
        "id",
        "name",
        "description",
        "tag",
        "type",
        "src_tcp_ports",
        "dest_tcp_ports",
        "src_udp_ports",
        "dest_udp_ports",
    ]
    for param_name in params:
        network_service[param_name] = module.params.get(param_name, None)
    service_id = network_service.get("id", None)
    service_name = network_service.get("name", None)
    existing_network_service = None
    if service_id is not None:
        existing_network_service = client.firewall.get_network_service(
            service_id
        ).to_dict()
    else:
        network_services = client.firewall.list_network_services().to_list()
        if service_name is not None:
            for svc in network_services:
                if svc.get("name", None) == service_name:
                    existing_network_service = svc
                    break

    # Normalize and compare existing and desired data
    normalized_service = normalize_service(network_service)
    normalized_existing_service = (
        normalize_service(existing_network_service) if existing_network_service else {}
    )

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in normalized_service.items():
        if (
            key not in fields_to_exclude
            and normalized_existing_service.get(key) != value
        ):
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing_service.get(key)}, Desired: {value}"
            )

    if existing_network_service is not None:
        id = existing_network_service.get("id")
        existing_network_service.update(normalized_service)
        existing_network_service["id"] = id

    module.warn(f"Final payload being sent to SDK: {normalized_service}")
    if state == "present":
        if existing_network_service is not None:
            if differences_detected:
                """Update"""
                update_service = deleteNone(
                    dict(
                        service_id=existing_network_service.get("id"),
                        name=existing_network_service.get("name"),
                        description=existing_network_service.get("description"),
                        type=existing_network_service.get("type"),
                        tag=existing_network_service.get("tag"),
                        src_tcp_ports=existing_network_service.get("src_tcp_ports"),
                        dest_tcp_ports=existing_network_service.get("dest_tcp_ports"),
                        src_udp_ports=existing_network_service.get("src_udp_ports"),
                        dest_udp_ports=existing_network_service.get("dest_udp_ports"),
                    )
                )
                module.warn("Payload Update for SDK: {}".format(update_service))
                update_service = client.firewall.update_network_service(
                    **update_service
                ).to_dict()
                module.exit_json(changed=True, data=update_service)
            else:
                module.exit_json(changed=False, data=existing_network_service)
        else:
            module.warn("Creating new service as no existing service found")
            """Create"""
            create_service = deleteNone(
                dict(
                    name=network_service.get("name"),
                    tag=network_service.get("tag"),
                    type=network_service.get("type"),
                    src_tcp_ports=network_service.get("src_tcp_ports"),
                    dest_tcp_ports=network_service.get("dest_tcp_ports"),
                    src_udp_ports=network_service.get("src_udp_ports"),
                    dest_udp_ports=network_service.get("dest_udp_ports"),
                    description=network_service.get("description"),
                )
            )
            module.warn("Payload for SDK: {}".format(create_service))
            create_service = client.firewall.add_network_service(
                **create_service
            ).to_dict()
            module.exit_json(changed=True, data=create_service)
    elif state == "absent":
        if existing_network_service is not None:
            service_type = existing_network_service.get("type")
            if service_type in ["PREDEFINED", "STANDARD"]:
                module.exit_json(
                    changed=False,
                    msg=f"Skipping deletion as the network service type '{service_type}' is protected.",
                )
            else:
                code = client.firewall.delete_network_service(
                    existing_network_service.get("id")
                )
                if code > 299:
                    module.fail_json(msg="Failed to delete the network service.")
                module.exit_json(
                    changed=True,
                    data=existing_network_service,
                    msg="Network service deleted successfully.",
                )
        else:
            module.exit_json(
                changed=False, msg="No matching network service found to delete."
            )


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        type=dict(
            type="str",
            required=False,
            default="CUSTOM",
            choices=["CUSTOM"],
        ),
        src_tcp_ports=dict(
            type="list",
            elements="dict",
            options=dict(
                start=dict(type="int", required=False),
                end=dict(type="int", required=False),
            ),
            required=False,
        ),
        dest_tcp_ports=dict(
            type="list",
            elements="dict",
            options=dict(
                start=dict(type="int", required=False),
                end=dict(type="int", required=False),
            ),
            required=False,
        ),
        src_udp_ports=dict(
            type="list",
            elements="dict",
            options=dict(
                start=dict(type="int", required=False),
                end=dict(type="int", required=False),
            ),
            required=False,
        ),
        dest_udp_ports=dict(
            type="list",
            elements="dict",
            options=dict(
                start=dict(type="int", required=False),
                end=dict(type="int", required=False),
            ),
            required=False,
        ),
        tag=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "ICMP_ANY",
                "UDP_ANY",
                "TCP_ANY",
                "OTHER_NETWORK_SERVICE",
                "DNS",
                "NETBIOS",
                "FTP",
                "GNUTELLA",
                "H_323",
                "HTTP",
                "HTTPS",
                "IKE",
                "IMAP",
                "ILS",
                "IKE_NAT",
                "IRC",
                "LDAP",
                "QUIC",
                "TDS",
                "NETMEETING",
                "NFS",
                "NTP",
                "SIP",
                "SNMP",
                "SMB",
                "SMTP",
                "SSH",
                "SYSLOG",
                "TELNET",
                "TRACEROUTE",
                "POP3",
                "PPTP",
                "RADIUS",
                "REAL_MEDIA",
                "RTSP",
                "VNC",
                "WHOIS",
                "KERBEROS_SEC",
                "TACACS",
                "SNMPTRAP",
                "NMAP",
                "RSYNC",
                "L2TP",
                "HTTP_PROXY",
                "PC_ANYWHERE",
                "MSN",
                "ECHO",
                "AIM",
                "IDENT",
                "YMSG",
                "SCCP",
                "MGCP_UA",
                "MGCP_CA",
                "VDO_LIVE",
                "OPENVPN",
                "TFTP",
                "FTPS_IMPLICIT",
                "ZSCALER_PROXY_NW_SERVICES",
                "GRE_PROTOCOL",
                "ESP_PROTOCOL",
                "DHCP",
            ],
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
