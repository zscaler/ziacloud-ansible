#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, Zscaler Technology Alliances <zscaler-partner-labs@z-bd.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_dlp_icap_servers_info
short_description: "Gets a the list of DLP servers using ICAP."
description:
  - "Gets a the list of DLP servers using ICAP."
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
  zscaler.ziacloud.zia_dlp_icap_servers_info:

- name: Gets a list of DLP ICAP Server by name
  zscaler.ziacloud.zia_dlp_icap_servers_info:
    name: "ZS_ICAP"
"""

RETURN = """
# Returns information about specific DLP ICAP Server.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    zia_argument_spec,
)
from zscaler import ZIA


def core(module: AnsibleModule):
    group_id = module.params.get("id", None)
    group_name = module.params.get("name", None)
    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )
    device_groups = []
    if group_id is not None:
        group = client.device_groups.list_device_groups(group_id).to_dict()
        device_groups = [group]
    else:
        device_groups = client.device_groups.list_devices().to_list()
        if group_name is not None:
            group = None
            for device in device_groups:
                if device.get("name", None) == group_name:
                    group = device
                    break
            if group is None:
                module.fail_json(
                    msg="Failed to retrieve device group: '%s'" % (group_name)
                )
            device_groups = [group]
    module.exit_json(changed=False, data=device_groups)


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
