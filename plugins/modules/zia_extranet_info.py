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
module: zia_extranet_info
short_description: "Gets information about ZIA extranets"
description:
  - "Gets extranet configurations for traffic forwarding."
  - "Retrieves a specific extranet by ID or name."
  - "If neither id nor name is provided, lists all extranets."
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
      - The unique identifier for the extranet.
    required: false
    type: int
  name:
    description:
      - The name of the extranet.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all extranets
  zscaler.ziacloud.zia_extranet_info:
    provider: '{{ provider }}'

- name: Get an extranet by ID
  zscaler.ziacloud.zia_extranet_info:
    provider: '{{ provider }}'
    id: 12345

- name: Get an extranet by name
  zscaler.ziacloud.zia_extranet_info:
    provider: '{{ provider }}'
    name: "My Extranet"
"""

RETURN = r"""
extranets:
  description: A list of extranets fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the extranet.
      returned: always
      type: int
    name:
      description: The name of the extranet.
      returned: always
      type: str
    description:
      description: The description of the extranet.
      returned: when available
      type: str
    extranet_dns_list:
      description: DNS servers specified for the extranet.
      returned: when available
      type: list
      elements: dict
      contains:
        id:
          description: The ID generated for the DNS server configuration.
          type: int
        name:
          description: The name of the DNS server.
          type: str
        primary_dns_server:
          description: The IP address of the primary DNS server.
          type: str
        secondary_dns_server:
          description: The IP address of the secondary DNS server.
          type: str
        use_as_default:
          description: Whether this DNS configuration is the designated default.
          type: bool
    extranet_ip_pool_list:
      description: Traffic selector IP pools specified for the extranet.
      returned: when available
      type: list
      elements: dict
      contains:
        id:
          description: The ID generated for the IP pool configuration.
          type: int
        name:
          description: The name of the IP pool.
          type: str
        ip_start:
          description: The starting IP address of the pool.
          type: str
        ip_end:
          description: The ending IP address of the pool.
          type: str
        use_as_default:
          description: Whether this IP pool is the designated default.
          type: bool
    created_at:
      description: Unix timestamp when the extranet was created.
      returned: when available
      type: int
    modified_at:
      description: Unix timestamp when the extranet was last modified.
      returned: when available
      type: int
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    extranet_id = module.params.get("id")
    extranet_name = module.params.get("name")

    client = ZIAClientHelper(module)

    if extranet_id is not None:
        result, _unused, error = client.traffic_extranet.get_extranet(extranet_id)
        if error:
            module.fail_json(msg=f"Failed to retrieve extranet with ID '{extranet_id}': {to_native(error)}")
        extranets_out = [result.as_dict()]
    else:
        result, _unused, error = client.traffic_extranet.list_extranets(query_params={"pageSize": 500})
        if error:
            module.fail_json(msg=f"Error retrieving extranets: {to_native(error)}")
        extranets_list = [e.as_dict() for e in result] if result else []

        if extranet_name:
            matched = None
            name_lower = extranet_name.lower()
            for e in extranets_list:
                if e.get("name", "").lower() == name_lower:
                    matched = e
                    break
            if matched is None:
                module.fail_json(msg=f"Extranet with name '{extranet_name}' not found.")
            extranets_out = [matched]
        else:
            extranets_out = extranets_list

    module.exit_json(changed=False, extranets=extranets_out)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
