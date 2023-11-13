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
module: zia_traffic_forwarding_static_ips_facts
short_description: "Gets static IP address for the specified ID"
description: "Gets static IP address for the specified ID"
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
    - zscaler.ziacloud.fragments.credentials_set
    - zscaler.ziacloud.fragments.provider
options:
  ip_address:
    description:
      - The static IP address
    required: true
    type: str
  id:
    description: "Static IP ID to retrieve"
    required: false
    type: int
"""

EXAMPLES = """
- name: Retrieve Details of All Static IPs.
  zscaler.ziacloud.zia_traffic_forwarding_static_ips_facts:

- name: Retrieve Details of Specific Static IPs By IP Address.
  zscaler.ziacloud.zia_traffic_forwarding_static_ips_facts:
    ip_address: 1.1.1.1

- name: Retrieve Details of Specific Static IPs By ID.
  zscaler.ziacloud.zia_traffic_forwarding_static_ips_facts:
    id: 82709

"""

RETURN = """
# Returns information on ZIA Static IP Addresses.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    static_ip_id = module.params.get("id", None)
    ip_address = module.params.get("ip_address", None)
    client = ZIAClientHelper(module)
    static_ips = []
    if static_ip_id is not None:
        static_ip = client.traffic.get_static_ip(static_ip_id).to_dict()
        static_ips = [static_ip]
    else:
        static_ips = client.traffic.list_static_ips().to_list()
        if ip_address is not None:
            static_ip = None
            for ip in static_ips:
                if ip.get("ip_address", None) == ip_address:
                    static_ip = ip
                    break
            if static_ip is None:
                module.fail_json(
                    msg="Failed to retrieve static ip address: '%s'" % (ip_address)
                )
            static_ips = [static_ip]
    module.exit_json(changed=False, data=static_ips)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        ip_address=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
