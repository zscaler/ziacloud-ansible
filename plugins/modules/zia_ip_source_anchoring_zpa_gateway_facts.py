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
module: zia_ip_source_anchoring_zpa_gateway_facts
short_description: "Gets the list of Zscaler Private Access (ZPA) gateways."
description:
  - "Gets the list of Zscaler Private Access (ZPA) gateways."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider

options:
  id:
    description: "A unique identifier assigned to the ZPA gateway"
    type: int
  name:
    description: "The name of the ZPA gateway"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all ZPA Gateways
  zscaler.ziacloud.zia_ip_source_anchoring_zpa_gateway_facts:
    provider: '{{ provider }}'

- name: Gather Information Details of ZPA Gateways By ID
  zscaler.ziacloud.zia_ip_source_anchoring_zpa_gateway_facts:
    provider: '{{ provider }}'
    id: "845875645"

- name: Gather Information Details of ZPA Gateways By Name
  zscaler.ziacloud.zia_ip_source_anchoring_zpa_gateway_facts:
    provider: '{{ provider }}'
    name: "USA-SJC37"
"""

RETURN = r"""
# Returns information on a specified ZIA Location.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    gateway_id = module.params.get("id", None)
    gateway_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    gateways = []
    if gateway_id is not None:
        gateway = client.zpa_gateway.get_gateway(gateway_id).to_dict()
        gateways = [gateway]
    else:
        gateways = client.zpa_gateway.list_gateways().to_list()
        if gateway_name is not None:
            gateway = None
            for gw in gateways:
                if gw.get("name", None) == gateway_name:
                    gateway = gw
                    break
            if gateway is None:
                module.fail_json(
                    msg="Failed to retrieve zpa gateway: '%s'" % (gateway_name)
                )
            gateways = [gateway]
    module.exit_json(changed=False, data=gateways)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
