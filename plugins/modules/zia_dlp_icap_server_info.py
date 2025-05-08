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
module: zia_dlp_icap_server_info
short_description: "Gets a the list of DLP servers using ICAP."
description:
  - "Gets a the list of DLP servers using ICAP."
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
    description: "The unique identifier for a DLP ICAP server."
    type: int
    required: false
  name:
    type: str
    required: false
    description:
      - The DLP ICAP server name.
"""

EXAMPLES = r"""
- name: Gets all list of DLP ICAP Server
  zscaler.ziacloud.zia_dlp_icap_server_info:
    provider: '{{ provider }}'

- name: Gets a list of DLP ICAP Server by name
  zscaler.ziacloud.zia_dlp_icap_server_info:
    provider: '{{ provider }}'
    name: "ZS_ICAP"
"""

RETURN = r"""
icaps:
  description: List of DLP ICAP servers retrieved from the Zscaler system.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Unique identifier for the DLP ICAP server.
      type: int
      returned: always
      sample: 1493
    name:
      description: Name of the DLP ICAP server.
      type: str
      returned: always
      sample: "ZS_BD_ICAP_01"
    status:
      description: Operational status of the DLP ICAP server.
      type: str
      returned: always
      sample: "ENABLED"
    url:
      description: The URL or endpoint of the ICAP server.
      type: str
      returned: always
      sample: "icaps://192.168.100.1:1344/"
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    icap_server_id = module.params.get("id")
    icap_server_name = module.params.get("name")

    client = ZIAClientHelper(module)
    icaps = []

    if icap_server_id is not None:
        icap_obj, _unused, error = client.dlp_resources.get_dlp_icap_servers(
            icap_server_id
        )
        if error or icap_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve DLP ICAP Server with ID '{icap_server_id}': {to_native(error)}"
            )
        icaps = [icap_obj.as_dict()]
    else:
        result, _unused, error = client.dlp_resources.list_dlp_icap_servers()
        if error:
            module.fail_json(
                msg=f"Error retrieving DLP ICAP Servers: {to_native(error)}"
            )

        icap_list = [i.as_dict() for i in result] if result else []

        if icap_server_name:
            matched = next(
                (i for i in icap_list if i.get("name") == icap_server_name), None
            )
            if not matched:
                available = [i.get("name") for i in icap_list]
                module.fail_json(
                    msg=f"DLP ICAP Server named '{icap_server_name}' not found. Available: {available}"
                )
            icaps = [matched]
        else:
            icaps = icap_list

    module.exit_json(changed=False, icaps=icaps)


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
