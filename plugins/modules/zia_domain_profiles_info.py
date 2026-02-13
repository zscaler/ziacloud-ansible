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
module: zia_domain_profiles_info
short_description: "Gets information about domain profiles"
description:
  - "Gets domain profile summaries for SaaS Security API."
  - "Retrieves a specific profile by profile_id or profile_name."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
    - Uses list_domain_profiles_lite API for domain profile data.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  profile_id:
    description:
      - The unique identifier for the domain profile.
    required: false
    type: int
  profile_name:
    description:
      - The name of the domain profile.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all domain profiles
  zscaler.ziacloud.zia_domain_profiles_info:
    provider: '{{ provider }}'

- name: Get a domain profile by ID
  zscaler.ziacloud.zia_domain_profiles_info:
    provider: '{{ provider }}'
    profile_id: 12345

- name: Get a domain profile by name
  zscaler.ziacloud.zia_domain_profiles_info:
    provider: '{{ provider }}'
    profile_name: "My Domain Profile"
"""

RETURN = r"""
profiles:
  description: A list of domain profiles fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    profile_id:
      description: The unique identifier for the domain profile.
      returned: always
      type: int
    profile_name:
      description: The name of the domain profile.
      returned: always
      type: str
    description:
      description: Additional notes or information about the domain profile.
      returned: when available
      type: str
    include_company_domains:
      description: Whether organizational domains are included in the profile.
      returned: when available
      type: bool
    include_subdomains:
      description: Whether subdomains are included.
      returned: when available
      type: bool
    custom_domains:
      description: List of custom domains for the profile.
      returned: when available
      type: list
    predefined_email_domains:
      description: List of predefined email service provider domains.
      returned: when available
      type: list
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    profile_id = module.params.get("profile_id")
    profile_name = module.params.get("profile_name")

    client = ZIAClientHelper(module)
    result, _unused, error = (
        client.saas_security_api.list_domain_profiles_lite()
    )
    if error:
        module.fail_json(
            msg=f"Error retrieving domain profiles: {to_native(error)}"
        )
    profiles_list = [p.as_dict() for p in result] if result else []

    matched = None
    for p in profiles_list:
        pid = p.get("profile_id")
        pname = p.get("profile_name")
        if profile_id is not None and pid == profile_id:
            matched = p
            break
        if profile_name and pname == profile_name:
            matched = p
            break

    if profile_id is not None or profile_name:
        if matched is None:
            module.fail_json(
                msg=f"Domain profile with name '{profile_name}' or id '{profile_id}' not found. "
                "Omit profile_id and profile_name to list all profiles."
            )
        profiles_out = [matched]
    else:
        profiles_out = profiles_list

    module.exit_json(changed=False, profiles=profiles_out)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        profile_id=dict(type="int", required=False),
        profile_name=dict(type="str", required=False),
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
