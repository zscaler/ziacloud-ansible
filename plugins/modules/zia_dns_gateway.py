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
module: zia_dns_gateway
short_description: "Adds a new DNS Gateway"
description:
  - "Adds a new DNS Gateway"
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
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
    description: "The unique identifier for the rule label."
    type: int
  name:
    description: Name of the DNS Gateway
    required: true
    type: str
  failure_behavior:
    description: Selects an action that must be performed if the configured DNS service is unavailable or unhealthy
    required: false
    type: str
    choices:
        - FAIL_RET_ERR
        - FAIL_ALLOW_IGNORE_DNAT
        - FAIL_FORWARD_TO_ZTR
  primary_ip_or_fqdn:
    description:
      - The IP address or the FQDN of the primary DNS service provided by the third-party DNS service provider
    required: false
    type: str
  secondary_ip_or_fqdn:
    description:
      - The IP address or the FQDN of the secondary DNS service provided by the third-party DNS service provider
    required: false
    type: str
  primary_ports:
    description:
      - Lists the ports for the primary DNS server depending on the protocols selected for the gateway.
    type: list
    elements: str
    required: false
  secondary_ports:
    description:
      - Lists the ports for the secondary DNS server depending on the protocols selected for the gateway.
    type: list
    elements: str
    required: false
  protocols:
    description:
        - Protocols that must be used to connect to the DNS service
    required: false
    type: list
    elements: str
    choices:
        - ANY
        - TCP
        - UDP
        - DOH
"""

EXAMPLES = r"""
- name: Create/Update/Delete DNS Gateway
  zscaler.ziacloud.zia_dns_gateway:
    name: DNSGatewayAnsible
    primary_ip_or_fqdn: "8.8.8.8"
    secondary_ip_or_fqdn: "4.4.4.4"
    failure_behavior: FAIL_RET_ERR
    protocols:
      - TCP
      - UDP
      - DOH
    primary_ports:
      - "53"
      - "53"
      - "443"
    secondary_ports:
      - "53"
      - "53"
      - "443"
"""

RETURN = r"""
# The newly created dns gateway resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_gateway(gateway):
    """
    Remove computed attributes from a dns gateway dict to make comparison easier.
    """
    normalized = gateway.copy() if gateway else {}
    computed_values = ["id"]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    gateway_params = {
        p: module.params.get(p)
        for p in [
            "id",
            "name",
            "primary_ip_or_fqdn",
            "secondary_ip_or_fqdn",
            "primary_ports",
            "secondary_ports",
            "failure_behavior",
            "protocols",
        ]
    }
    gateway_id = gateway_params.get("id")
    gateway_name = gateway_params.get("name")

    existing_gateway = None

    if gateway_id:
        result, _unused, error = client.dns_gatways.get_dns_gateways(gateway_id)
        if error:
            module.fail_json(
                msg=f"Error fetching gateway with id {gateway_id}: {to_native(error)}"
            )
        existing_gateway = result.as_dict()
    else:
        result, _unused, error = client.dns_gatways.list_dns_gateways()
        if error:
            module.fail_json(msg=f"Error listing dns gateways: {to_native(error)}")
        gateway_list = [gw.as_dict() for gw in result]
        if gateway_name:
            for gw in gateway_list:
                if gw.get("name") == gateway_name:
                    existing_gateway = gw
                    break

    normalized_desired = normalize_gateway(gateway_params)
    normalized_existing = (
        normalize_gateway(existing_gateway) if existing_gateway else {}
    )

    differences_detected = False
    unordered_fields = ["protocols", "primary_ports", "secondary_ports"]

    for key, desired_value in normalized_desired.items():
        current_value = normalized_existing.get(key)

        if (
            key in unordered_fields
            and isinstance(desired_value, list)
            and isinstance(current_value, list)
        ):
            if set(map(str, desired_value)) != set(map(str, current_value)):
                differences_detected = True
                module.warn(
                    f"Difference detected in {key} (unordered). Current: {current_value}, Desired: {desired_value}"
                )
        else:
            if current_value != desired_value:
                differences_detected = True
                module.warn(
                    f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
                )

    if module.check_mode:
        if state == "present" and (existing_gateway is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_gateway:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_gateway:
            if differences_detected:
                gateway_id_to_update = existing_gateway.get("id")
                if not gateway_id_to_update:
                    module.fail_json(
                        msg="Cannot update gateway: ID is missing from the existing resource."
                    )

                updated_gateway, _unused, error = client.dns_gatways.update_dns_gateway(
                    gateway_id=gateway_id_to_update,
                    name=gateway_params.get("name"),
                    primary_ip_or_fqdn=gateway_params.get("primary_ip_or_fqdn"),
                    secondary_ip_or_fqdn=gateway_params.get("secondary_ip_or_fqdn"),
                    failure_behavior=gateway_params.get("failure_behavior"),
                    protocols=gateway_params.get("protocols"),
                    primary_ports=gateway_params.get("primary_ports"),
                    secondary_ports=gateway_params.get("secondary_ports"),
                )
                if error:
                    module.fail_json(msg=f"Error updating gateway: {to_native(error)}")
                module.exit_json(changed=True, data=updated_gateway.as_dict())
            else:
                module.exit_json(changed=False, data=existing_gateway)
        else:
            new_gateway, _unused, error = client.dns_gatways.add_dns_gateway(
                name=gateway_params.get("name"),
                primary_ip_or_fqdn=gateway_params.get("primary_ip_or_fqdn"),
                secondary_ip_or_fqdn=gateway_params.get("secondary_ip_or_fqdn"),
                failure_behavior=gateway_params.get("failure_behavior"),
                protocols=gateway_params.get("protocols"),
                primary_ports=gateway_params.get("primary_ports"),
                secondary_ports=gateway_params.get("secondary_ports"),
            )
            if error:
                module.fail_json(msg=f"Error adding gateway: {to_native(error)}")
            module.exit_json(changed=True, data=new_gateway.as_dict())

    elif state == "absent":
        if existing_gateway:
            gateway_id_to_delete = existing_gateway.get("id")
            if not gateway_id_to_delete:
                module.fail_json(
                    msg="Cannot delete gateway: ID is missing from the existing resource."
                )

            _unused, _unused, error = client.dns_gatways.delete_dns_gateway(
                gateway_id_to_delete
            )
            if error:
                module.fail_json(msg=f"Error deleting gateway: {to_native(error)}")
            module.exit_json(changed=True, data=existing_gateway)
        else:
            module.exit_json(changed=False, data={})

    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            id=dict(type="int", required=False),
            name=dict(type="str", required=True),
            primary_ip_or_fqdn=dict(type="str", required=False),
            secondary_ip_or_fqdn=dict(type="str", required=False),
            failure_behavior=dict(
                type="str",
                required=False,
                choices=[
                    "FAIL_RET_ERR",
                    "FAIL_ALLOW_IGNORE_DNAT",
                    "FAIL_FORWARD_TO_ZTR",
                ],
            ),
            protocols=dict(
                type="list",
                elements="str",
                required=False,
                choices=[
                    "ANY",
                    "TCP",
                    "UDP",
                    "DOH",
                ],
            ),
            primary_ports=dict(
                type="list",
                elements="str",
                required=False,
            ),
            secondary_ports=dict(
                type="list",
                elements="str",
                required=False,
            ),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
