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
module: zia_cloud_browser_isolation_profile_info
short_description: Retrieves cloud browser isolation profile.
description: Retrieves a cloud browser isolation profile.
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
        - The universally unique identifier (UUID) for the browser isolation profile.
    type: str
    required: false
  name:
    description:
        - Name of the browser isolation profile.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of a Cloud Browser Isolation Profiles
  zscaler.ziacloud.zia_cloud_browser_isolation_profile_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a Cloud Browser Isolation Profiles by Name
  zscaler.ziacloud.zia_cloud_browser_isolation_profile_info:
    provider: '{{ provider }}'
    name: "Example"

- name: Gather Information Details of a Cloud Browser Isolation Profiles by ID
  zscaler.ziacloud.zia_cloud_browser_isolation_profile_info:
    provider: '{{ provider }}'
    name: "123456-1234-5678-9101-7d416881fae4"
"""

RETURN = r"""
profiles:
  description: List of cloud browser profiles retrieved from the Zscaler system.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Unique identifier for the profile.
      type: str
      returned: always
      sample: "6d2402e9-0c3b-4f56-9d30-7d416881fae4"
    name:
      description: Name of the profile.
      type: str
      returned: always
      sample: "BD_SA_Profile1_ZIA"
    profile_seq:
      description: Sequence number of the profile, used internally for ordering.
      type: int
      returned: always
      sample: 0
    url:
      description: URL to access the profile details on the Zscaler portal.
      type: str
      returned: always
      sample: "https://redirect.isolation.zscaler.com/tenant/d374ac83d089/profile/6d2402e9-0c3b-4f56-9d30-7d416881fae4"
    default_profile:
      description: Indicates if the profile is the default profile.
      type: bool
      returned: when applicable
      sample: true
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

    result, _unused, error = client.cloud_browser_isolation.list_isolation_profiles()
    if error:
        module.fail_json(msg=f"Error retrieving isolation profiles: {to_native(error)}")

    all_profiles = [p.as_dict() for p in result] if result else []

    # Apply in-memory filtering
    profiles = []
    if profile_id:
        profiles = [p for p in all_profiles if str(p.get("id")) == str(profile_id)]
        if not profiles:
            module.fail_json(msg=f"Isolation profile with ID '{profile_id}' not found.")
    elif profile_name:
        profiles = [p for p in all_profiles if p.get("name") == profile_name]
        if not profiles:
            module.fail_json(msg=f"Isolation profile with name '{profile_name}' not found.")
    else:
        profiles = all_profiles

    module.exit_json(changed=False, profiles=profiles)


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
