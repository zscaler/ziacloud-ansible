#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, Zscaler Technology Alliances <zscaler-partner-labs@z-bd.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_location_groups_info
short_description: "Gets locations only, not sub-locations."
description:
  - "Gets locations only, not sub-locations."
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
    description: "Unique identifier for the location group"
    required: false
    type: int
  name:
    description: "Location group name"
    required: false
    type: str
"""

EXAMPLES = """
- name: Gather Information Details of all ZIA Locations
  zscaler.ziacloud.zia_location_groups_info:

- name: Gather Information Details of ZIA Location Group By ID
  zscaler.ziacloud.zia_location_groups_info:
    name: "845875645"

- name: Gather Information Details of ZIA Location Group By Name
  zscaler.ziacloud.zia_location_groups_info:
    name: "USA-SJC37"
"""

RETURN = """
# Returns information on a specified ZIA Location.
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
    locations = []
    if group_id is not None:
        location = client.locations.get_location_group_lite_by_id(group_id).to_dict()
        locations = [location]
    else:
        locations = client.locations.list_location_groups_lite().to_list()
        if group_name is not None:
            location = None
            for loc in locations:
                if loc.get("name", None) == group_name:
                    location = loc
                    break
            if location is None:
                module.fail_json(
                    msg="Failed to retrieve ip source group: '%s'" % (group_name)
                )
            locations = [location]
    module.exit_json(changed=False, data=locations)


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
