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

DOCUMENTATION = r"""
---
module: zia_user_management_facts
short_description: "Gets a list of users"
description:
  - "Gets a list of users"
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider

options:
  id:
    description: "User ID."
    required: false
    type: int
  name:
    description: "User name. This appears when choosing users for policies."
    required: true
    type: str
"""

EXAMPLES = r"""
- name: Gets a list of all users
  zscaler.ziacloud.zia_user_management_facts:
    provider: '{{ provider }}'

- name: Gets a list of a single user
  zscaler.ziacloud.zia_user_management_facts:
    provider: '{{ provider }}'
    name: "Adam Ashcroft"
"""

RETURN = r"""
# Returns information of all users.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    user_id = module.params.get("id", None)
    user_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    users = []
    if user_id is not None:
        user = client.users.get_user(user_id).to_dict()
        users = [user]
    else:
        users = client.users.list_users().to_list()
        if user_name is not None:
            user = None
            for usr in users:
                if usr.get("name", None) == user_name:
                    user = usr
                    break
            if user is None:
                module.fail_json(msg="Failed to retrieve user: '%s'" % (user_name))
            users = [user]
    module.exit_json(changed=False, data=users)


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
