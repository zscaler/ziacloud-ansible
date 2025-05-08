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
module: zia_ip_source_anchoring_zpa_gateway_info
short_description: "Gets the list of Zscaler Private Access (ZPA) gateways."
description:
  - "Gets the list of Zscaler Private Access (ZPA) gateways."
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
    description: "A unique identifier assigned to the ZPA gateway"
    type: int
    required: false
  name:
    description: "The name of the ZPA gateway"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all ZPA Gateways
  zscaler.ziacloud.zia_ip_source_anchoring_zpa_gateway_info:
    provider: '{{ provider }}'

- name: Gather Information Details of ZPA Gateways By ID
  zscaler.ziacloud.zia_ip_source_anchoring_zpa_gateway_info:
    provider: '{{ provider }}'
    id: "845875645"

- name: Gather Information Details of ZPA Gateways By Name
  zscaler.ziacloud.zia_ip_source_anchoring_zpa_gateway_info:
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
    gateway_id = module.params.get("id")
    gateway_name = module.params.get("name")

    client = ZIAClientHelper(module)
    gateways = []

    if gateway_id is not None:
        gateway_obj, _unused, error = client.zpa_gateway.get_gateway(gateway_id)
        if error or gateway_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve ZPA Gateway with ID '{gateway_id}': {to_native(error)}"
            )
        gateways = [gateway_obj.as_dict()]
    else:
        query_params = {}
        if gateway_name:
            query_params["search"] = gateway_name

        result, _unused, error = client.zpa_gateway.list_gateways(
            query_params=query_params
        )
        if error:
            module.fail_json(msg=f"Error retrieving ZPA Gateways: {to_native(error)}")

        gateway_list = [g.as_dict() for g in result] if result else []

        if gateway_name:
            matched = next(
                (g for g in gateway_list if g.get("name") == gateway_name), None
            )
            if not matched:
                available = [g.get("name") for g in gateway_list]
                module.fail_json(
                    msg=f"ZPA Gateway named '{gateway_name}' not found. Available: {available}"
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
