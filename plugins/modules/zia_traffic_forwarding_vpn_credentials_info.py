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
module: zia_traffic_forwarding_vpn_credentials_info
short_description: "Gets VPN credentials that can be associated to locations"
description:
  - "Gets VPN credentials that can be associated to locations"
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
    description:
      - VPN credential id
    required: false
    type: int
  fqdn:
    description: "Fully Qualified Domain Name. Applicable only to UFQDN or XAUTH (or HOSTED_MOBILE_USERS) auth type."
    required: false
    type: str
  ip_address:
    description:
        - This is a required field for IP auth type and is not applicable to other auth types.
    required: false
    type: str
"""

EXAMPLES = r"""

- name: Retrieve Details of All ZPN Credentials.
  zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_info:
    provider: '{{ provider }}'

- name: Retrieve Details of Specific ZPN Credentials By fqdn.
  zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_info:
    provider: '{{ provider }}'
    fqdn: "sjc-1-37@acme.com"

- name: Retrieve Details of Specific ZPN Credentials By IP Address.
  zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_info:
    provider: '{{ provider }}'
    ip_address: '1.1.1.1'

- name: Retrieve Details of Specific ZPN Credentials By ID.
  zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_info:
    provider: '{{ provider }}'
    id: 222
"""

RETURN = r"""
credentials:
  description: A list of VPN credentials retrieved based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the VPN credential.
      returned: always
      type: int
      sample: 108667023
    type:
      description: The type of VPN credential, which could be 'UFQDN' or 'IP'.
      returned: always
      type: str
      sample: "UFQDN"
    fqdn:
      description: The Fully Qualified Domain Name associated with the VPN credential.
      returned: when type is 'UFQDN'
      type: str
      sample: "sjc-1-37@acme.com"
    ip_address:
      description: The IP address associated with the VPN credential.
      returned: when type is 'IP'
      type: str
      sample: "1.1.1.1"
    comments:
      description: Any additional comments or metadata associated with the VPN credential.
      returned: always
      type: str
      sample: "San Jose VPN Credential 37"
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    collect_all_items
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper


def core(module):
    vpn_id = module.params.get("id")
    fqdn = module.params.get("fqdn")
    ip_address = module.params.get("ip_address")

    client = ZIAClientHelper(module)
    credentials = []

    if vpn_id is not None:
        vpn_obj, _, error = client.traffic_vpn_credentials.get_vpn_credential(credential_id=vpn_id)
        if error or vpn_obj is None:
            module.fail_json(msg=f"Failed to retrieve VPN credential with ID '{vpn_id}': {to_native(error)}")
        credentials = [vpn_obj.as_dict()]
    else:
        query_params = {}

        # Set implicit search
        if fqdn:
            query_params["search"] = fqdn
        elif ip_address:
            query_params["search"] = ip_address

        # Add additional filters
        for param in ["type", "include_only_without_location", "location_id", "managed_by"]:
            val = module.params.get(param)
            if val is not None:
                query_params[param] = val

        result, err = collect_all_items(client.traffic_vpn_credentials.list_vpn_credentials, query_params or None)
        if err:
            module.fail_json(msg=f"Error retrieving VPN credentials: {to_native(err)}")

        credentials = [c.as_dict() if hasattr(c, "as_dict") else c for c in result] if result else []

    module.exit_json(changed=False, credentials=credentials)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        fqdn=dict(type="str", required=False),
        ip_address=dict(type="str", required=False),
        type=dict(type="str", required=False, choices=["CN", "IP", "UFQDN", "XAUTH"]),
        include_only_without_location=dict(type="bool", required=False),
        location_id=dict(type="int", required=False),
        managed_by=dict(type="int", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        mutually_exclusive=[["id", "fqdn", "ip"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
