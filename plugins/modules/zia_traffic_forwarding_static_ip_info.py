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
module: zia_traffic_forwarding_static_ip_info
short_description: "Gets static IP address for the specified ID"
description: "Gets static IP address for the specified ID"
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
  ip_address:
    description:
      - The static IP address
    required: false
    type: str
  id:
    description: "Static IP ID to retrieve"
    required: false
    type: int
"""

EXAMPLES = r"""
- name: Retrieve Details of All Static IPs.
  zscaler.ziacloud.zia_traffic_forwarding_static_ip_info:
    provider: '{{ provider }}'

- name: Retrieve Details of Specific Static IPs By IP Address.
  zscaler.ziacloud.zia_traffic_forwarding_static_ip_info:
    provider: '{{ provider }}'
    ip_address: 1.1.1.1

- name: Retrieve Details of Specific Static IPs By ID.
  zscaler.ziacloud.zia_traffic_forwarding_static_ip_info:
    provider: '{{ provider }}'
    id: 82709
"""

RETURN = r"""
static_ips:
  description: A list of Static IP configuration details retrieved.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the Static IP.
      returned: always
      type: int
      sample: 3687136
    ip_address:
      description: The IP address of the Static IP configuration.
      returned: always
      type: str
      sample: "1.1.1.1"
    geo_override:
      description: Indicates if the geolocation has been manually overridden.
      returned: always
      type: bool
      sample: false
    routable_ip:
      description: Specifies if the IP address is routable on the Internet.
      returned: always
      type: bool
      sample: true
    city:
      description: Details about the city associated with the Static IP.
      returned: always
      type: dict
      contains:
        id:
          description: The unique identifier for the city.
          returned: always
          type: int
          sample: 3448439
        name:
          description: The name of the city, including additional location details.
          returned: always
          type: str
          sample: "California, san Jose, United States"
    latitude:
      description: The latitude coordinate of the Static IP.
      returned: always
      type: float
      sample: -23.6283
    longitude:
      description: The longitude coordinate of the Static IP.
      returned: always
      type: float
      sample: -46.6409
    last_modification_time:
      description: The Unix timestamp when the Static IP was last modified.
      returned: always
      type: int
      sample: 1721348015
    last_modified_by:
      description: Information about the user who last modified the Static IP.
      returned: always
      type: dict
      contains:
        id:
          description: The unique identifier of the user who last modified the entry.
          returned: always
          type: int
          sample: 44772836
        name:
          description: The username of the person who last modified the entry.
          returned: always
          type: str
          sample: "DEFAULT ADMIN"
"""


from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    static_ip_id = module.params.get("id")
    ip_address = module.params.get("ip_address")

    client = ZIAClientHelper(module)
    static_ips = []

    if static_ip_id is not None:
        ip_obj, _unused, error = client.traffic_static_ip.get_static_ip(static_ip_id)
        if error or ip_obj is None:
            module.fail_json(msg=f"Failed to retrieve static IP with ID '{static_ip_id}': {to_native(error)}")
        static_ips = [ip_obj.as_dict()]
    else:
        query_params = {}

        if ip_address:
            query_params["ip_address"] = ip_address

        result, _unused, error = client.traffic_static_ip.list_static_ips(query_params=query_params if query_params else None)
        if error:
            module.fail_json(msg=f"Error retrieving static IPs: {to_native(error)}")

        ip_list = [ip.as_dict() for ip in result] if result else []

        if ip_address:
            matched = next((ip for ip in ip_list if ip.get("ip_address") == ip_address), None)
            if not matched:
                available = [ip.get("ip_address") for ip in ip_list]
                module.fail_json(msg=f"Static IP '{ip_address}' not found. Available: {available}")
            static_ips = [matched]
        else:
            static_ips = ip_list

    module.exit_json(changed=False, static_ips=static_ips)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        ip_address=dict(type="str", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["id", "ip_address"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
