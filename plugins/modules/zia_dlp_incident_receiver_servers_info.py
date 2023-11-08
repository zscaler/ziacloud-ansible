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
module: zia_dlp_incident_receiver_servers_info
short_description: "Gets a list of DLP Incident Receivers."
description:
  - "Gets a list of DLP Incident Receivers."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
options:
  username:
    description: "Username of admin user that is provisioned"
    required: true
    type: str
  password:
    description: "Password of the admin user"
    required: true
    type: str
  api_key:
    description: "The obfuscated form of the API key"
    required: true
    type: str
  base_url:
    description: "The host and basePath for the cloud services API"
    required: true
    type: str
  id:
    description: "The unique identifier for the Incident Receiver."
    required: false
    type: int
  name:
    type: str
    required: false
    description:
      - The Incident Receiver server name.
"""

EXAMPLES = """
- name: Gets all list of DLP Incident Receiver Server
  zscaler.ziacloud.zia_dlp_incident_receiver_servers_info:

- name: Gets a list of DLP Incident Receiver Server by name
  zscaler.ziacloud.zia_dlp_incident_receiver_servers_info:
    name: "ZIR_BD_SA01
"
"""

RETURN = """
# Returns information about specific DLP Incident Receiver Server.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    zia_argument_spec,
)
from zscaler import ZIA


def core(module: AnsibleModule):
    receiver_id = module.params.get("id", None)
    receiver_name = module.params.get("name", None)
    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )
    receivers = []
    if receiver_id is not None:
        receiver = client.dlp.get_dlp_incident_receiver(receiver_id).to_dict()
        receivers = [receiver]
    else:
        receivers = client.dlp.list_dlp_incident_receiver().to_list()
        if receiver_name is not None:
            receiver = None
            for dlp in receivers:
                if dlp.get("name", None) == receiver_name:
                    receiver = dlp
                    break
            if receiver is None:
                module.fail_json(
                    msg="Failed to retrieve dlp incident receiver server: '%s'" % (receiver_name)
                )
            receivers = [receiver]
    module.exit_json(changed=False, data=receivers)


def main():
    argument_spec = zia_argument_spec()
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
