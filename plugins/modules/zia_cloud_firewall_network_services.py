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
notes:
    - Check mode is supported.
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
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import deleteNone
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper


def normalize_service(service):
    """
    Normalize network service data:
    - Removes non-drift-relevant fields
    - Sorts all port range blocks by (start, end)
    """
    normalized = service.copy() if service else {}

    def sorted_ports(port_list):
        if not port_list:
            return []
        return sorted(port_list, key=lambda p: (p.get("start", 0), p.get("end", 0)))

    for key in ["src_tcp_ports", "dest_tcp_ports", "src_udp_ports", "dest_udp_ports"]:
        if key in normalized:
            normalized[key] = sorted_ports(normalized[key])

    # Clean up computed fields
    for field in ["creatorContext", "isNameL10nTag", "id"]:
        normalized.pop(field, None)

    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    network_service = {
        p: module.params.get(p)
        for p in [
            "id", "name", "description", "tag", "type",
            "src_tcp_ports", "dest_tcp_ports", "src_udp_ports", "dest_udp_ports"
        ]
    }

    service_id = network_service.get("id")
    service_name = network_service.get("name")
    existing = None

    if service_id:
        result, _, error = client.cloud_firewall.get_network_service(service_id)
        if error:
            module.fail_json(msg=f"Error fetching service ID {service_id}: {to_native(error)}")
        existing = result.as_dict()
    elif service_name:
        result, _, error = client.cloud_firewall.list_network_services()
        if error:
            module.fail_json(msg=f"Error listing services: {to_native(error)}")
        for svc in result:
            svc_dict = svc.as_dict()
            if svc_dict.get("name") == service_name:
                existing = svc_dict
                break

    normalized_desired = normalize_service(network_service)
    normalized_existing = normalize_service(existing)

    differences_detected = any(
        normalized_desired.get(k) != normalized_existing.get(k)
        for k in normalized_desired
    )

    if module.check_mode:
        if state == "present" and (not existing or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if existing:
        existing.update(normalized_desired)
        existing["id"] = existing.get("id") or service_id

    if state == "present":
        if existing:
            if differences_detected:
                if not existing.get("id"):
                    module.fail_json(msg="Missing ID for update.")

                payload = deleteNone(dict(
                    service_id=existing.get("id"),
                    name=network_service.get("name"),
                    description=network_service.get("description"),
                    tag=network_service.get("tag"),
                    type=network_service.get("type"),
                    src_tcp_ports=network_service.get("src_tcp_ports"),
                    dest_tcp_ports=network_service.get("dest_tcp_ports"),
                    src_udp_ports=network_service.get("src_udp_ports"),
                    dest_udp_ports=network_service.get("dest_udp_ports"),
                ))

                updated, _, error = client.cloud_firewall.update_network_service(**payload)
                if error:
                    module.fail_json(msg=f"Error updating service: {to_native(error)}")
                module.exit_json(changed=True, data=updated.as_dict())
            else:
                module.exit_json(changed=False, data=existing)
        else:
            payload = deleteNone(dict(
                name=network_service.get("name"),
                description=network_service.get("description"),
                tag=network_service.get("tag"),
                type=network_service.get("type"),
                src_tcp_ports=network_service.get("src_tcp_ports"),
                dest_tcp_ports=network_service.get("dest_tcp_ports"),
                src_udp_ports=network_service.get("src_udp_ports"),
                dest_udp_ports=network_service.get("dest_udp_ports"),
            ))

            created, _, error = client.cloud_firewall.add_network_service(**payload)
            if error:
                module.fail_json(msg=f"Error creating service: {to_native(error)}")
            module.exit_json(changed=True, data=created.as_dict())

    elif state == "absent":
        if existing:
            service_type = existing.get("type")
            if service_type in ["PREDEFINED", "STANDARD"]:
                module.exit_json(changed=False, msg=f"Skipping delete of protected type: {service_type}")
            _, _, error = client.cloud_firewall.delete_network_service(existing.get("id"))
            if error:
                module.fail_json(msg=f"Error deleting service: {to_native(error)}")
            module.exit_json(changed=True, data=existing, msg="Service deleted")
        else:
            module.exit_json(changed=False, msg="Service not found")

    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        type=dict(
            type="str", default="CUSTOM",
            choices=["CUSTOM"]
        ),
        src_tcp_ports=dict(
            type="list", elements="dict", required=False,
            options=dict(start=dict(type="int"), end=dict(type="int")),
        ),
        dest_tcp_ports=dict(
            type="list", elements="dict", required=False,
            options=dict(start=dict(type="int"), end=dict(type="int")),
        ),
        src_udp_ports=dict(
            type="list", elements="dict", required=False,
            options=dict(start=dict(type="int"), end=dict(type="int")),
        ),
        dest_udp_ports=dict(
            type="list", elements="dict", required=False,
            options=dict(start=dict(type="int"), end=dict(type="int")),
        ),
        tag=dict(
            type="list", elements="str", required=False,
            choices=[
                "ICMP_ANY", "UDP_ANY", "TCP_ANY", "OTHER_NETWORK_SERVICE", "DNS",
                "NETBIOS", "FTP", "GNUTELLA", "H_323", "HTTP", "HTTPS", "IKE", "IMAP",
                "ILS", "IKE_NAT", "IRC", "LDAP", "QUIC", "TDS", "NETMEETING", "NFS",
                "NTP", "SIP", "SNMP", "SMB", "SMTP", "SSH", "SYSLOG", "TELNET",
                "TRACEROUTE", "POP3", "PPTP", "RADIUS", "REAL_MEDIA", "RTSP", "VNC",
                "WHOIS", "KERBEROS_SEC", "TACACS", "SNMPTRAP", "NMAP", "RSYNC", "L2TP",
                "HTTP_PROXY", "PC_ANYWHERE", "MSN", "ECHO", "AIM", "IDENT", "YMSG",
                "SCCP", "MGCP_UA", "MGCP_CA", "VDO_LIVE", "OPENVPN", "TFTP",
                "FTPS_IMPLICIT", "ZSCALER_PROXY_NW_SERVICES", "GRE_PROTOCOL",
                "ESP_PROTOCOL", "DHCP",
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
