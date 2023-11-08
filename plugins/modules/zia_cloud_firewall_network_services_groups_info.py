#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, Zscaler Technology Alliances <zscaler-partner-labs@z-bd.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_cloud_firewall_network_services_groups_info
short_description: "Gets a list of all network service groups."
description:
  - "Gets a list of all network service groups."
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
"""

EXAMPLES = """
- name: Gather Information Details of all network services groups
  zscaler.ziacloud.zia_fw_filtering_network_services_groups_info:

- name: Gather Information Details of a specific network services group
  zscaler.ziacloud.zia_fw_filtering_network_services_groups_info:
    name: "Corporate Custom SSH TCP_10022"
"""

RETURN = """
# Returns information on a specific Network Services Groups.
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
    service_groups = []

    if group_id is not None:
        service_group = client.firewall.get_network_svc_group(group_id).to_dict()
        service_groups = [service_group]
    else:
        service_groups = client.firewall.list_network_svc_groups(
            search=group_name
        ).to_list()
        if not service_groups:
            module.fail_json(
                msg="Failed to retrieve network services group: '%s'" % (group_name)
            )
        elif group_name is not None:
            service_group = None
            for service in service_groups:
                if service.get("name", None) == group_name:
                    service_group = service
                    break

            if service_group is None:
                module.fail_json(
                    msg="Failed to retrieve network services group: '%s'. Available services: %s"
                    % (group_name, service_groups)
                )
            service_groups = [service_group]

    module.exit_json(changed=False, data=service_groups)


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
