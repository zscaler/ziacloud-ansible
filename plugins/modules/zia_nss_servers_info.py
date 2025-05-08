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
module: zia_nss_servers_info
short_description: "Retrieves a list of registered NSS servers"
description:
  - "Retrieves a list of registered NSS servers"
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
    description: "System-generated identifier of the NSS server based on the software platform"
    type: int
    required: false
  name:
    description: "NSS server name"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets all list of nss servers
  zscaler.ziacloud.zia_nss_servers_info:
    provider: '{{ provider }}'

- name: Gets a list of nss server by name
  zscaler.ziacloud.zia_nss_servers_info:
    provider: '{{ provider }}'
    name: "NSSServer01"
"""

RETURN = r"""
servers:
  description: A list of nss servers fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the nss server.
      returned: always
      type: int
      sample: 3687131
    name:
      description: The name of the nss server.
      returned: always
      type: str
      sample: "Example"
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    nss_id = module.params.get("id")
    nss_name = module.params.get("name")

    client = ZIAClientHelper(module)
    servers = []

    if nss_id is not None:
        nss_obj, _unused, error = client.nss_servers.get_nss_server(nss_id)
        if error or nss_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve NSS Server with ID '{nss_id}': {to_native(error)}"
            )
        servers = [nss_obj.as_dict()]
    else:
        query_params = {}
        if nss_name:
            query_params["search"] = nss_name

        result, _unused, error = client.nss_servers.list_nss_servers(
            query_params=query_params
        )
        if error:
            module.fail_json(msg=f"Error retrieving NSS Servers: {to_native(error)}")

        nss_list = [g.as_dict() for g in result] if result else []

        if nss_name:
            matched = next((g for g in nss_list if g.get("name") == nss_name), None)
            if not matched:
                available = [g.get("name") for g in nss_list]
                module.fail_json(
                    msg=f"NSS Server with name '{nss_name}' not found. Available servers: {available}"
                )
            servers = [matched]
        else:
            servers = nss_list

    module.exit_json(changed=False, servers=servers)


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
