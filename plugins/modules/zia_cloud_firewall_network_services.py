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

DOCUMENTATION = """
---
module: zia_cloud_firewall_network_services
short_description: "Adds a new network service."
description: "Adds a new network service."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
options:

  id:
    description: "The unique identifier for the rule label"
    required: false
    type: int
  name:
    description: "The rule label name"
    required: true
    type: str
  tag:
    description: "The rule label name"
    required: false
    type: str
    choices: [ 'ICMP_ANY', 'UDP_ANY', 'TCP_ANY', 'OTHER_NETWORK_SERVICE', 'DNS', 'NETBIOS',
                'FTP', 'GNUTELLA', 'H_323', 'HTTP', 'HTTPS', 'IKE', 'IMAP', 'ILS', 'IKE_NAT',
                'IRC', 'LDAP', 'QUIC', 'TDS', 'NETMEETING', 'NFS', 'NTP', 'SIP', 'SNMP', 'SMB',
                'SMTP', 'SSH', 'SYSLOG', 'TELNET', 'TRACEROUTE', 'POP3', 'PPTP', 'RADIUS', 'REAL_MEDIA',
                'RTSP', 'VNC', 'WHOIS', 'KERBEROS_SEC', 'TACACS', 'SNMPTRAP', 'NMAP', 'RSYNC', 'L2TP',
                'HTTP_PROXY', 'PC_ANYWHERE', 'MSN', 'ECHO', 'AIM', 'IDENT', 'YMSG', 'SCCP', 'MGCP_UA',
                'MGCP_CA', 'VDO_LIVE', 'OPENVPN', 'TFTP', 'FTPS_IMPLICIT', 'ZSCALER_PROXY_NW_SERVICES',
                'GRE_PROTOCOL', 'ESP_PROTOCOL, DHCP' ]
  src_tcp_ports:
    type: list
    elements: dict
    description:
      - List of tcp port range pairs, e.g. ['35000', '35000'] for port 35000.
    required: false
    suboptions:
      start:
        type: int
        required: false
        description:
          - List of valid TCP ports.
      end:
        type: int
        required: false
        description:
          - List of valid TCP ports.
  dest_tcp_ports:
    type: list
    elements: dict
    description:
      - List of tcp port range pairs, e.g. ['35000', '35000'] for port 35000.
    required: false
    suboptions:
      start:
        type: int
        required: false
        description:
          - List of valid TCP ports.
      end:
        type: int
        required: false
        description:
          - List of valid TCP ports.
  src_udp_ports:
    type: list
    elements: dict
    description:
      - List of tcp port range pairs, e.g. ['35000', '35000'] for port 35000.
    required: false
    suboptions:
      start:
        type: int
        required: false
        description:
          - List of valid TCP ports.
      end:
        type: int
        required: false
        description:
          - List of valid TCP ports.
  dest_udp_ports:
    type: list
    elements: dict
    description:
      - List of tcp port range pairs, e.g. ['35000', '35000'] for port 35000.
    required: false
    suboptions:
      start:
        type: int
        required: false
        description:
          - List of valid TCP ports.
      end:
        type: int
        required: false
        description:
          - List of valid TCP ports.
  type:
    description: ""
    required: false
    type: str
    choices:
        - STANDARD
        - PREDEFINED
        - CUSTOM
    default: STANDARD
  description:
    description: ""
    required: false
    type: str
  is_name_l10n_tag:
    description: ""
    required: false
    default: false
    type: bool
"""

EXAMPLES = """

- name: Create/Update/Delete Network Services.
  zscaler.ziacloud.zia_fw_filtering_network_services:
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

RETURN = """
# The newly created network services resource record.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    network_service = dict()
    params = [
        "id",
        "name",
        "description",
        "tag",
        "src_tcp_ports",
        "dest_tcp_ports",
        "src_udp_ports",
        "dest_udp_ports",
        "is_name_l10n_tag",
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
    if existing_network_service is not None:
        id = existing_network_service.get("id")
        existing_network_service.update(network_service)
        existing_network_service["id"] = id
    if state == "present":
        if existing_network_service is not None:
            """Update"""
            existing_network_service = client.firewall.update_network_service(
                service_id=existing_network_service.get("id", ""),
                name=existing_network_service.get("name", ""),
                tag=existing_network_service.get("tag", ""),
                src_tcp_ports=existing_network_service.get("src_tcp_ports", ""),
                dest_tcp_ports=existing_network_service.get("dest_tcp_ports", ""),
                src_udp_ports=existing_network_service.get("src_udp_ports", ""),
                dest_udp_ports=existing_network_service.get("dest_udp_ports", ""),
                description=existing_network_service.get("description", ""),
                is_name_l10n_tag=existing_network_service.get("is_name_l10n_tag", ""),
            ).to_dict()
            module.exit_json(changed=True, data=existing_network_service)
        else:
            """Create"""
            network_service = client.firewall.add_network_service(
                name=network_service.get("name", ""),
                tag=network_service.get("tag", ""),
                src_tcp_ports=network_service.get("src_tcp_ports", ""),
                dest_tcp_ports=network_service.get("dest_tcp_ports", ""),
                src_udp_ports=network_service.get("src_udp_ports", ""),
                dest_udp_ports=network_service.get("dest_udp_ports", ""),
                description=network_service.get("description", ""),
                is_name_l10n_tag=network_service.get("is_name_l10n_tag", ""),
            ).to_dict()
            module.exit_json(changed=False, data=network_service)
    elif state == "absent":
        if existing_network_service is not None:
            code = client.firewall.delete_network_service(
                existing_network_service.get("id")
            )
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_network_service)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        is_name_l10n_tag=dict(type="bool", default=False, required=False),
        type=dict(
            type="str",
            required=False,
            default="STANDARD",
            choices=["STANDARD", "PREDEFINED", "CUSTOM"],
        ),
        src_tcp_ports=dict(
            type="list",
            elements="dict",
            options=dict(
                id=dict(type="int", required=False),
                start=dict(type="int", required=False),
                end=dict(type="int", required=False),
            ),
            required=False,
        ),
        dest_tcp_ports=dict(
            type="list",
            elements="dict",
            options=dict(
                id=dict(type="int", required=False),
                start=dict(type="int", required=False),
                end=dict(type="int", required=False),
            ),
            required=False,
        ),
        src_udp_ports=dict(
            type="list",
            elements="dict",
            options=dict(
                id=dict(type="int", required=False),
                start=dict(type="int", required=False),
                end=dict(type="int", required=False),
            ),
            required=False,
        ),
        dest_udp_ports=dict(
            type="list",
            elements="dict",
            options=dict(
                id=dict(type="int", required=False),
                start=dict(type="int", required=False),
                end=dict(type="int", required=False),
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
