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
module: zia_dns_gateway_info
short_description: "Retrieves a list of DNS Gateways"
description:
  - "Retrieves a list of DNS Gateways"
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  id:
    description: "The unique identifier for the DNS Gateway"
    type: int
    required: false
  name:
    description: "The DNS Gateway name."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets a list of all DNS Gateways
  zscaler.ziacloud.zia_dns_gateway_info:
    provider: '{{ provider }}'

- name: Gets the DNS Gateway by name
  zscaler.ziacloud.zia_dns_gateway_info:
    provider: '{{ provider }}'
    name: "DNSGW01"

- name: Gets the DNS Gateway by ID
  zscaler.ziacloud.zia_dns_gateway_info:
    provider: '{{ provider }}'
    id: 97687667
"""

RETURN = r"""
gateways:
  description: A list of DNS Gateways fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the DNS Gateway.
      type: int
      returned: always
      sample: 18442171
    name:
      description: The name of the DNS Gateway.
      type: str
      returned: always
      sample: "DNSGatewayAnsible"
    dns_gateway_type:
      description: The type of DNS Gateway. Typically defaults to `OFW_PDNS_REDIR_GW`.
      type: str
      returned: always
      sample: "OFW_PDNS_REDIR_GW"
    primary_ip_or_fqdn:
      description: IP address or FQDN of the primary DNS service provided by your DNS service provider.
      type: str
      returned: always
      sample: "8.8.8.8"
    secondary_ip_or_fqdn:
      description: IP address or FQDN of the secondary DNS service provided by your DNS service provider.
      type: str
      returned: always
      sample: "4.4.4.4"
    primary_ports:
      description: List of ports used to connect to the primary DNS service.
      type: list
      elements: str
      returned: always
      sample: ["53", "53", "443"]
    secondary_ports:
      description: List of ports used to connect to the secondary DNS service.
      type: list
      elements: str
      returned: always
      sample: ["53", "53", "443"]
    failure_behavior:
      description: Action to perform if the configured DNS service is unavailable or unhealthy.
      type: str
      returned: always
      sample: "FAIL_RET_ERR"
    protocols:
      description: Protocols used to connect to the DNS service.
      type: list
      elements: str
      returned: always
      sample: ["TCP", "UDP", "DOH"]
    auto_created:
      description: Indicates whether the DNS Gateway was automatically created.
      type: bool
      returned: always
      sample: false
    nat_ztr_gateway:
      description: Indicates whether the gateway uses NAT with Zscaler Trusted Resolver.
      type: bool
      returned: always
      sample: false
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    gateway_id = module.params.get("id")
    gateway_name = module.params.get("name")

    client = ZIAClientHelper(module)
    gateways = []

    if gateway_id is not None:
        gateway_obj, _unused, error = client.dns_gatways.get_dns_gateways(gateway_id)
        if error or gateway_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve DNS Gateway with ID '{gateway_id}': {to_native(error)}"
            )
        gateways = [gateway_obj.as_dict()]
    else:
        query_params = {}
        if gateway_name:
            query_params["search"] = gateway_name

        result, _unused, error = client.dns_gatways.list_dns_gateways(
            query_params=query_params
        )
        if error:
            module.fail_json(msg=f"Error retrieving DNS Gateways: {to_native(error)}")

        gateway_list = [g.as_dict() for g in result] if result else []

        if gateway_name:
            matched = next(
                (g for g in gateway_list if g.get("name") == gateway_name), None
            )
            if not matched:
                available = [g.get("name") for g in gateway_list]
                module.fail_json(
                    msg=f"DNS Gateway with name '{gateway_name}' not found. Available gateways: {available}"
                )
            gateways = [matched]
        else:
            gateways = gateway_list

    module.exit_json(changed=False, gateways=gateways)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
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
