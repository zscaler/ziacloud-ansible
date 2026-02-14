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
module: zia_admin_roles_info
short_description: "Gets a list of admin roles"
description:
  - "Gets a list of admin roles"
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
    description:
      - Admin role ID.
    type: int
    required: false
  name:
    description:
      - Name of the admin role.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets a list of all admin roles
  zscaler.ziacloud.zia_admin_role_management_info:
  provider: '{{ provider }}'

- name: Gets a list of an admin roles
  zscaler.ziacloud.zia_admin_role_management_info:
    provider: '{{ provider }}'
    name: "Engineering"
"""

RETURN = r"""
roles:
  description: >-
    List of roles returned from Zscaler ZIA based on the provided criteria. Each element in the list
    is a dictionary that describes a role.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the admin role.
      type: int
      returned: always
      sample: 26270
    name:
      description: The name of the admin role.
      type: str
      returned: always
      sample: "Engineering_Role"
    rank:
      description: The rank associated with the admin role.
      type: int
      returned: when available
      sample: 7
    report_time_duration:
      description: The time duration for reporting, represented in minutes. A value of -1 may indicate unlimited or not applicable.
      type: int
      returned: when available
      sample: -1
    role_type:
      description: The type of the admin role, indicating the role's scope and permissions.
      type: str
      returned: always
      sample: "EXEC_INSIGHT_AND_ORG_ADMIN"
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    role_id = module.params.get("id", None)
    role_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    roles = []

    if role_id:
        # Get role by ID
        result, _unused, error = client.admin_roles.get_role(role_id)
        if error:
            module.fail_json(msg=f"Error fetching role with id {role_id}: {to_native(error)}")
        if result:
            roles = [result.as_dict()]
    else:
        # List roles with optional name filter
        query_params = {}
        if role_name:
            query_params["search"] = role_name

        result, _unused, error = client.admin_roles.list_roles(query_params=query_params)
        if error:
            module.fail_json(msg=f"Error listing roles: {to_native(error)}")

        roles = [role.as_dict() for role in result] if result else []

        # If name was specified but not found in search, try exact match
        if role_name and not roles:
            result, _unused, error = client.admin_roles.list_roles()
            if error:
                module.fail_json(msg=f"Error listing all roles: {to_native(error)}")

            all_roles = [role.as_dict() for role in result] if result else []
            for role in all_roles:
                if role.get("name") == role_name:
                    roles = [role]
                    break

    module.exit_json(changed=False, roles=roles)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[("name", "id")],
    )
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
