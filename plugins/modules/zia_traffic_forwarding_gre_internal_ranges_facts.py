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

DOCUMENTATION = r"""
---
module: zia_traffic_forwarding_gre_internal_ranges_facts
short_description: "available GRE tunnel internal IP address ranges"
description: "Gets the next available GRE tunnel internal IP address ranges"
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider

options:
  start_ip_address:
    description: Starting IP address in the range
    required: true
    type: str
  end_ip_address:
    description: Ending IP address in the range
    required: true
    type: str
  internal_ip_range:
    description: Internal IP range information
    required: false
    type: str
  static_ip:
    description: Static IP information
    required: false
    type: str
  limit:
    description: The maximum number of GRE tunnel IP ranges that can be added
    required: false
    type: int
    default: 10
"""

EXAMPLES = r"""
- name: Retrieve Details of All GRE Internal Ranges.
  zscaler.ziacloud.zia_traffic_forwarding_gre_internal_ranges_facts:
    provider: '{{ provider }}'

- name: Retrieve Details of Specific GRE Internal Range.
  zscaler.ziacloud.zia_traffic_forwarding_gre_internal_ranges_facts:
    provider: '{{ provider }}'
    start_ip_address: 1.1.1.1
    end_ip_address:
"""

RETURN = r"""
# Returns information about GRE Internal Ranges.
"""


from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    # Retrieve parameters
    internal_ip_range = module.params.get("internal_ip_range", None)
    static_ip = module.params.get("static_ip", None)
    start_ip_address = module.params.get("start_ip_address", None)
    end_ip_address = module.params.get("end_ip_address", None)
    limit = module.params.get("limit", 10)  # Set default limit to 10 if not provided

    client = ZIAClientHelper(module)

    # Create a dictionary of query parameters
    query_params = {}
    if internal_ip_range:
        query_params["internalIpRange"] = internal_ip_range
    if static_ip:
        query_params["staticIp"] = static_ip
    if start_ip_address:
        query_params["startIpAddress"] = start_ip_address
    if end_ip_address:
        query_params["endIpAddress"] = end_ip_address
    query_params["limit"] = limit

    # Debugging: Print the query parameters to check if they are set correctly
    # module.warn("Query Parameters: {}".format(query_params))

    # Call the SDK method with the query parameters
    gre_ranges = client.traffic.list_gre_ranges(**query_params).to_list()

    # Debugging: Print the number of ranges returned
    module.warn("Number of GRE Ranges Returned: {}".format(len(gre_ranges)))

    # Return the response
    module.exit_json(changed=False, data=gre_ranges)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        internal_ip_range=dict(type="str", required=False),
        static_ip=dict(type="str", required=False),
        start_ip_address=dict(type="str", required=False),
        end_ip_address=dict(type="str", required=False),
        limit=dict(type="int", required=False, default=10),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
