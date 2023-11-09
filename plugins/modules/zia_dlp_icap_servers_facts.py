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
module: zia_dlp_icap_servers_facts
short_description: "Gets a the list of DLP servers using ICAP."
description:
  - "Gets a the list of DLP servers using ICAP."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
    - zscaler.ziacloud.fragments.credentials_set
    - zscaler.ziacloud.fragments.provider
options:
  id:
    description: "The unique identifier for a DLP ICAP server."
    required: false
    type: int
  name:
    type: str
    required: false
    description:
      - The DLP ICAP server name.
"""

EXAMPLES = """
- name: Gets all list of DLP ICAP Server
  zscaler.ziacloud.zia_dlp_icap_servers_facts:

- name: Gets a list of DLP ICAP Server by name
  zscaler.ziacloud.zia_dlp_icap_servers_facts:
    name: "ZS_ICAP"
"""

RETURN = """
# Returns information about specific DLP ICAP Server.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    icap_server_id = module.params.get("id", None)
    icap_server_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    icaps = []
    if icap_server_id is not None:
        icap = client.dlp.get_dlp_icap_servers(icap_server_id).to_dict()
        icaps = [icap]
    else:
        icaps = client.dlp.list_dlp_icap_servers().to_list()
        if icap_server_name is not None:
            icap = None
            for dlp in icaps:
                if dlp.get("name", None) == icap_server_name:
                    icap = dlp
                    break
            if icap is None:
                module.fail_json(
                    msg="Failed to retrieve dlp icap server: '%s'" % (icap_server_name)
                )
            icaps = [icap]
    module.exit_json(changed=False, data=icaps)


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
