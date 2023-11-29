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
module: zia_admin_role_management_facts
short_description: "Gets a list of admin roles"
description:
  - "Gets a list of admin roles"
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
    - zscaler.ziacloud.fragments.credentials_set
    - zscaler.ziacloud.fragments.provider
options:

  id:
    description: "Admin role ID."
    required: false
    type: int
  name:
    description: "Name of the admin role."
    required: true
    type: str
"""

EXAMPLES = """
- name: Gets a list of all admin roles
  zscaler.ziacloud.zia_admin_role_management_facts:

- name: Gets a list of an admin roles
  zscaler.ziacloud.zia_admin_role_management_facts:
    name: "marketing"
"""

RETURN = """
# Returns information of all admin roles.
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
    if role_id is not None:
        role = client.admin_and_role_management.get_role(role_id).to_dict()
        roles = [role]
    else:
        roles = client.admin_and_role_management.list_roles().to_list()
        if role_name is not None:
            role = None
            for rol in roles:
                if rol.get("name", None) == role_name:
                    role = rol
                    break
            if role is None:
                module.fail_json(
                    msg="Failed to retrieve admin role: '%s'" % (role_name)
                )
            roles = [role]
    module.exit_json(changed=False, data=roles)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
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
