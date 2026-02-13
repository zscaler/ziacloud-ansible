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
module: zia_tenant_restriction_profile_info
short_description: "Gets information about tenant restriction profiles"
description:
  - "Gets tenant restriction profiles for cloud app control."
  - "Retrieves a specific profile by ID or name."
  - "If neither id nor name is provided, lists all profiles."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
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
      - The unique identifier for the tenant restriction profile.
    required: false
    type: int
  name:
    description:
      - The tenant restriction profile name.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all tenant restriction profiles
  zscaler.ziacloud.zia_tenant_restriction_profile_info:
    provider: '{{ provider }}'

- name: Get a tenant restriction profile by ID
  zscaler.ziacloud.zia_tenant_restriction_profile_info:
    provider: '{{ provider }}'
    id: 1254654

- name: Get a tenant restriction profile by name
  zscaler.ziacloud.zia_tenant_restriction_profile_info:
    provider: '{{ provider }}'
    name: "MS Profile 01"
"""

RETURN = r"""
profiles:
  description: A list of tenant restriction profiles fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    profile_id = module.params.get("id")
    profile_name = module.params.get("name")

    client = ZIAClientHelper(module)

    if profile_id is not None:
        result, _unused, error = client.tenancy_restriction_profile.get_restriction_profile(
            profile_id
        )
        if error:
            module.fail_json(
                msg=f"Failed to retrieve tenant restriction profile with ID '{profile_id}': {to_native(error)}"
            )
        profiles_out = [result.as_dict()]
    else:
        query_params = {"search": profile_name} if profile_name else {}
        result, _unused, error = client.tenancy_restriction_profile.list_restriction_profile(
            query_params=query_params if query_params else None
        )
        if error:
            module.fail_json(
                msg=f"Error retrieving tenant restriction profiles: {to_native(error)}"
            )
        profiles_list = [p.as_dict() for p in result] if result else []

        if profile_name:
            matched = next(
                (p for p in profiles_list if p.get("name") == profile_name),
                None,
            )
            if matched is None:
                module.fail_json(
                    msg=f"Tenant restriction profile with name '{profile_name}' not found."
                )
            profiles_out = [matched]
        else:
            profiles_out = profiles_list

    module.exit_json(changed=False, profiles=profiles_out)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
