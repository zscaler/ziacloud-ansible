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
module: zia_traffic_forwarding_gre_internal_ranges_info
short_description: "available GRE tunnel internal IP address ranges"
description: "Gets the next available GRE tunnel internal IP address ranges"
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
  start_ip_address:
    description: Starting IP address in the range
    required: false
    type: str
  end_ip_address:
    description: Ending IP address in the range
    required: false
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
  zscaler.ziacloud.zia_traffic_forwarding_gre_internal_ranges_info:
    provider: '{{ provider }}'

- name: Retrieve Details of Specific GRE Internal Range.
  zscaler.ziacloud.zia_traffic_forwarding_gre_internal_ranges_info:
    provider: '{{ provider }}'
    internal_ip_range: '172.17.47.247-172.17.47.240'
"""

RETURN = r"""
gre_ranges:
  description: List of GRE internal IP ranges retrieved from the system.
  returned: always
  type: list
  elements: dict
  contains:
    start_ip_address:
      description: The starting IP address of the GRE range.
      type: str
      returned: always
      sample: "172.20.225.56"
    end_ip_address:
      description: The ending IP address of the GRE range.
      type: str
      returned: always
      sample: "172.20.225.63"
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper


def core(module):
    internal_ip_range = module.params.get("internal_ip_range")
    static_ip = module.params.get("static_ip")
    limit = module.params.get("limit")

    client = ZIAClientHelper(module)

    query_params = {}

    if internal_ip_range:
        query_params["internal_ip_range"] = internal_ip_range
    if static_ip:
        query_params["static_ip"] = static_ip
    if limit is not None:
        query_params["limit"] = limit

    result, _, error = client.gre_tunnel.list_gre_ranges(query_params=query_params if query_params else None)
    if error:
        module.fail_json(msg=f"Error retrieving GRE ranges: {to_native(error)}")

    gre_ranges = result if result else []

    module.exit_json(changed=False, gre_ranges=gre_ranges)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        internal_ip_range=dict(type="str", required=False),
        static_ip=dict(type="str", required=False),
        limit=dict(type="int", required=False, default=10),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
