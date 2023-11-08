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
module: zia_admin_user_info
short_description: ""
description:
  - ""
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
options:
  id:
    description: "Admin or auditor's user ID"
    required: false
    type: int
  login_name:
    description:
        - Admin or auditor's login name.
        - LoginName is in email format and uses the domain name associated to the Zscaler account.
    required: false
    type: str
  username:
    description: Admin or auditor's username.
    required: false
    type: str
  email:
    description: Admin or auditor's email address
    required: false
    type: str
"""

EXAMPLES = """
- name: Gather Information Details of All Admin Users
  willguibr.ziacloud.zia_admin_user_info:

- name: Gather Information Details of an Admin User by LoginName
  willguibr.ziacloud.zia_admin_user_info:
    login_name: "john.smith@acme.com"

- name: Gather Information Details of Admin User by Username
  willguibr.ziacloud.zia_admin_user_info:
    username: "John Smith"

- name: Gather Information Details of Admin User by Email
  willguibr.ziacloud.zia_admin_user_info:
    email: "john.smith@acme.com"
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



def core(module: AnsibleModule):
    admin_id = module.params.get("id", None)
    admin_login_name = module.params.get("login_name", None)
    admin_username = module.params.get("username", None)
    admin_email = module.params.get("email", None)
    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )
    admins = []
    if admin_id is not None:
        admin = client.admin_and_role_management.get_user(admin_id=admin_id)
        if admin is None:
            module.fail_json(msg="Failed to retrieve Admin User ID: '%s'" % (id))
        admins = [admin]
    elif admin_login_name is not None:
        admin = client.admin_and_role_management.get_user(admin_login_name)
        if admin is None:
            module.fail_json(
                msg="Failed to retrieve Admin User Login Name: '%s'"
                % (admin_login_name)
            )
        admins = [admin]
    elif admin_username is not None:
        admin = client.admin_and_role_management.get_user(admin_username)
        if admin is None:
            module.fail_json(
                msg="Failed to retrieve Admin User Name: '%s'" % (admin_username)
            )
        admins = [admin]
    elif admin_email is not None:
        admin = client.admin_and_role_management.get_user(admin_email)
        if admin is None:
            module.fail_json(
                msg="Failed to retrieve Admin User Email: '%s'" % (admin_email)
            )
        admins = [admin]
    else:
        admins = client.admin_and_role_management.list_users()
    module.exit_json(changed=False, data=admins)


def main():
    argument_spec = zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="str", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
