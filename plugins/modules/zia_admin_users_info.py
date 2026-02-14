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
module: zia_admin_users_info
short_description: "Gets a list of admin users"
description:
  - "Gets a list of admin users"
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
      - Admin user ID.
    type: int
    required: false
  login_name:
    description:
      - Admin or auditor login name
    required: false
    type: str
  user_name:
    description:
      - Admin or auditor's username
    required: false
    type: str
  include_auditor_users:
    description:
      - Include or exclude auditor user information in the list.
    required: false
    type: bool
  include_admin_users:
    description:
      - Include or exclude admin user information in the list.
    required: false
    type: bool
"""

EXAMPLES = r"""
- name: Gets a list of all admin userrs
  zscaler.ziacloud.zia_admin_users_info:
  provider: '{{ provider }}'

- name: Gets a admin users by name
  zscaler.ziacloud.zia_admin_users_info:
    provider: '{{ provider }}'
    name: "Engineering"

- name: Gets a admin users by ID
  zscaler.ziacloud.zia_admin_users_info:
    provider: '{{ provider }}'
    id: 7788656
"""

RETURN = r"""
admins:
  description: >-
    List of roles returned from Zscaler ZIA based on the provided criteria. Each element in the list
    is a dictionary that describes a user.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the admin user.
      type: int
      returned: always
      sample: 26270
    name:
      description: The name of the admin user.
      type: str
      returned: always
      sample: "John Doe"
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    user_id = module.params.get("id", None)
    login_name = module.params.get("login_name", None)
    user_name = module.params.get("user_name", None)
    include_auditor_users = module.params.get("include_auditor_users", None)
    include_admin_users = module.params.get("include_admin_users", None)

    client = ZIAClientHelper(module)
    users = []

    if user_id:
        result, _unused, error = client.admin_users.get_admin_user(user_id)
        if error:
            module.fail_json(msg=f"Error fetching user with id {user_id}: {to_native(error)}")
        if result:
            users = [result.as_dict()]
    else:
        query_params = {}

        # Support search string via login_name or username
        search_string = login_name or user_name
        if search_string:
            query_params["search"] = search_string

        if include_auditor_users is not None:
            query_params["include_auditor_users"] = include_auditor_users
        if include_admin_users is not None:
            query_params["include_admin_users"] = include_admin_users

        result, _unused, error = client.admin_users.list_admin_users(query_params=query_params)
        if error:
            module.fail_json(msg=f"Error listing users: {to_native(error)}")

        users = [user.as_dict() for user in result] if result else []

        # Fallback: do exact match if initial search returned nothing
        if search_string and not users:
            result, _unused, error = client.admin_users.list_admin_users()
            if error:
                module.fail_json(msg=f"Error listing all users: {to_native(error)}")

            all_users = [user.as_dict() for user in result] if result else []
            for user in all_users:
                if user.get("loginName") == login_name or user.get("name") == user_name:
                    users = [user]
                    break

    module.exit_json(changed=False, users=users)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        login_name=dict(type="str", required=False),
        user_name=dict(type="str", required=False),
        include_auditor_users=dict(type="bool", required=False, default=None),
        include_admin_users=dict(type="bool", required=False, default=None),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,  # optional, can be omitted
        mutually_exclusive=[("id", "login_name"), ("id", "user_name")],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
