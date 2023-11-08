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
module: zia_cloud_firewall_network_services_groups
short_description: "Adds a new network service group."
description:
  - "Adds a new network service group."
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
    description: ""
    required: false
    type: int
  name:
    description: ""
    required: true
    type: str
  services:
    type: list
    elements: dict
    description: ""
    required: false
    suboptions:
        id:
            description: "The unique identifier for the rule label"
            required: false
            type: int
        name:
            description: "The rule label name"
            required: true
            type: str
  state:
    description:
      - Whether the app connector group should be present or absent.
    type: str
    choices:
        - present
        - absent
    default: present
"""

EXAMPLES = """

- name: Create/Update/Delete Network Services Groups.
  zscaler.ziacloud.zia_fw_filtering_network_services_groups:
    name: "example"
    description: "example"
    services:
        - name: [ "UDP_ANY", "TCP_ANY" ]

"""

RETURN = """
# The newly created network services groups resource record.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    zia_argument_spec,
)
from zscaler import ZIA


def core(module):
    state = module.params.get("state", None)
    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )
    service_group = dict()
    params = [
        "id",
        "name",
        "description",
        "service_ids",
    ]
    for param_name in params:
        service_group[param_name] = module.params.get(param_name, None)
    group_id = service_group.get("id", None)
    group_name = service_group.get("name", None)
    existing_service_group = None
    if group_id is not None:
        existing_service_group = client.firewall.get_network_svc_group(
            group_id
        ).to_dict()
    else:
        service_groups = client.firewall.list_network_svc_groups().to_list()
        if group_name is not None:
            for svc in service_groups:
                if svc.get("name", None) == group_name:
                    existing_service_group = svc
                    break
    if existing_service_group is not None:
        id = existing_service_group.get("id")
        existing_service_group.update(service_group)
        existing_service_group["id"] = id
    if state == "present":
        if existing_service_group is not None:
            """Update"""
            existing_service_group = client.firewall.update_network_svc_group(
                group_id=existing_service_group.get("id", ""),
                name=existing_service_group.get("name", ""),
                service_ids=existing_service_group.get("service_ids", ""),
                description=existing_service_group.get("description", ""),
            ).to_dict()
            module.exit_json(changed=True, data=existing_service_group)
        else:
            """Create"""
            service_group = client.firewall.add_network_svc_group(
                name=service_group.get("name", ""),
                service_ids=service_group.get("service_ids", ""),
                description=service_group.get("description", ""),
            ).to_dict()
            module.exit_json(changed=False, data=service_group)
    elif state == "absent":
        if existing_service_group is not None:
            code = client.firewall.delete_network_svc_group(
                existing_service_group.get("id")
            )
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_service_group)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = zia_argument_spec()
    id_name_spec = dict(
        type="list",
        elements="str",
        required=True,
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        service_ids=id_name_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
