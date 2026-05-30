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
module: zia_email_profiles_info
short_description: "Gets a list of ZIA Email Profiles"
description:
  - "Gets a list of ZIA Email Profiles, optionally filtered by ID or name."
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
    description: "The unique identifier for the email profile."
    type: int
    required: false
  name:
    description: "The name of the email profile."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets all email profiles
  zscaler.ziacloud.zia_email_profiles_info:
    provider: '{{ provider }}'

- name: Gets an email profile by name
  zscaler.ziacloud.zia_email_profiles_info:
    provider: '{{ provider }}'
    name: "Example"
"""

RETURN = r"""
profiles:
  description: A list of email profiles fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the email profile.
      returned: always
      type: int
      sample: 3687131
    name:
      description: The name of the email profile.
      returned: always
      type: str
      sample: "Example"
    description:
      description: Additional information about the email profile.
      returned: always
      type: str
      sample: "Example email profile"
    emails:
      description: The list of email addresses associated with the email profile.
      returned: always
      type: list
      elements: str
      sample: ["john.doe@example.com"]
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    collect_all_items,
)


def core(module):
    profile_id = module.params.get("id")
    profile_name = module.params.get("name")

    client = ZIAClientHelper(module)
    profiles = []

    if profile_id is not None:
        result, _unused, error = client.email_profiles.get_email_profile(profile_id)
        if error or result is None:
            module.fail_json(msg=f"Failed to retrieve Email Profile with ID '{profile_id}': {to_native(error)}")
        profiles = [result.as_dict()]
    else:
        query_params = {}
        if profile_name:
            query_params["search"] = profile_name

        result, err = collect_all_items(client.email_profiles.list_email_profiles, query_params)
        if err:
            module.fail_json(msg=f"Error retrieving Email Profiles: {to_native(err)}")

        profile_list = [p.as_dict() if hasattr(p, "as_dict") else p for p in result] if result else []

        if profile_name:
            matched = next((p for p in profile_list if p.get("name") == profile_name), None)
            if not matched:
                available = [p.get("name") for p in profile_list]
                module.fail_json(msg=f"Email Profile with name '{profile_name}' not found. Available profiles: {available}")
            profiles = [matched]
        else:
            profiles = profile_list

    module.exit_json(changed=False, profiles=profiles)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["name", "id"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
