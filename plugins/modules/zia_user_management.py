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
module: zia_user_management
short_description: "Adds a new user."
description:
  - Adds a new user. A user can belong to multiple groups, but can only belong to one department.
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
    description: "User ID"
    required: false
    type: int
  name:
    description: "User name. This appears when choosing users for policies."
    required: false
    type: str
  email:
    description:
        - User email consists of a user name and domain name.
        - It does not have to be a valid email address, but it must be unique and its domain must belong to the organization.
    required: false
    type: str
  groups:
    description:
        - User email consists of a user name and domain name.
        - It does not have to be a valid email address, but it must be unique and its domain must belong to the organization.
    type: list
    elements: str
    required: false
  department:
    description:
        - Department a user belongs to.
    type: list
    elements: str
    required: false
  comments:
    description:
        - Additional information about this user.
    required: false
    type: str
  temp_auth_email:
    description:
        - Temporary Authentication Email.
        - If you enabled one-time tokens or links, enter the email address to which the Zscaler service sends the tokens or links.
        - If this is empty, the service sends the email to the User email.
    required: false
    type: str
  password:
    description:
        - User's password. Applicable only when authentication type is Hosted DB.
        - Password strength must follow what is defined in the auth settings.
    required: false
    type: str
"""

EXAMPLES = """
- name: Gather Information Details of a ZIA User Role
  zscaler.ziacloud.zia_user_management_users:

- name: Gather Information Details of a ZIA Admin User by Name
  zscaler.ziacloud.zia_user_management_users:
    name: "IOS"
"""

RETURN = """
# Returns information on a specified ZIA Admin User.
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
    local_user = dict()
    params = [
        "id",
        "name",
        "email",
        "groups",
        "department",
        "comments",
        "temp_auth_email",
        "password",
    ]
    for param_name in params:
        local_user[param_name] = module.params.get(param_name, None)
    user_id = local_user.get("id", None)
    user_name = local_user.get("name", None)
    existing_user = None
    if user_id is not None:
        existing_user = client.users.get_user(
          user_id
        ).to_dict()
    else:
        local_users = client.users.list_users().to_list()
        if user_name is not None:
            for user in local_users:
                if user.get("name", None) == user_name:
                    existing_user = user
                    break
    if existing_user is not None:
        id = existing_user.get("id")
        existing_user.update(local_user)
        existing_user["id"] = id
    if state == "present":
        if existing_user is not None:
            """Update"""
            existing_user = client.users.update_user(
                user_id=existing_user.get("id", ""),
                name=existing_user.get("name", ""),
                email=existing_user.get("email", ""),
                groups=existing_user.get("groups", ""),
                department=existing_user.get("department", ""),
                comments=existing_user.get("comments", ""),
                temp_auth_email=existing_user.get("temp_auth_email", ""),
                password=existing_user.get("password", ""),
            ).to_dict()
            module.exit_json(changed=True, data=existing_user)
        else:
            """Create"""
            local_user = client.users.add_user(
                name=local_user.get("name", ""),
                email=local_user.get("email", ""),
                groups=local_user.get("groups", ""),
                department=local_user.get("department", ""),
                comments=local_user.get("comments", ""),
                temp_auth_email=local_user.get("temp_auth_email", ""),
                password=local_user.get("password", ""),
            ).to_dict()
            module.exit_json(changed=False, data=local_user)
    elif state == "absent":
        if existing_user is not None:
            code = client.users.delete_user(
              existing_user.get("id")
            )
            if code > 299:
                  module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_user)
        module.exit_json(changed=False, data={})


def main():
    argument_spec = zia_argument_spec()
    id_spec = dict(
        type="list",
        elements="str",
        required=False,
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        email=dict(type="str", required=True),
        comments=dict(type="str", required=False),
        temp_auth_email=dict(type="str", required=False),
        password=dict(type="str", no_log=True, required=True),
        department=dict(type="int", required=True),
        groups=id_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
