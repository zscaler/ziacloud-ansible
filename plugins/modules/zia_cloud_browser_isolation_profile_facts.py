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
module: zia_cloud_browser_isolation_profile_facts
short_description: "Gets all cloud browser isolation profiles"
description: "Gets all cloud browser isolation profiles"
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.credentials_set
options:
  id:
    description: "The universally unique identifier (UUID) for the browser isolation profile"
    required: false
    type: str
  name:
    description: "Name of the browser isolation profile"
    required: true
    type: str
"""

EXAMPLES = """
- name: Gather Information Details of a Cloud Browser Isolation Profiles
  zscaler.ziacloud.zia_cloud_browser_isolation_profile_facts:

- name: Gather Information Details of a Cloud Browser Isolation Profiles by Name
  zscaler.ziacloud.zia_cloud_browser_isolation_profile_facts:
    name: "Example"

- name: Gather Information Details of a Cloud Browser Isolation Profiles by ID
  zscaler.ziacloud.zia_cloud_browser_isolation_profile_facts:
    name: "791c2d14-e9a7-4c47-8a3c-8988caad925b"
"""

RETURN = """
# Returns information on a specified ZIA Cloud Browser Isolation Profile.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    profile_id = module.params.get("id", None)
    profile_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    profiles = []

    if profile_id is not None:
        # Fetch rule by ID
        profilesBox = client.isolation_profile.get_profiles_by_id(profile_id=profile_id)
        if profilesBox is None:
            module.fail_json(
                msg="Failed to retrieve cloud browser profile ID: '%s'" % (profile_id)
            )
        profiles = [profilesBox.to_dict()]
    else:
        # Fetch all profiles and search by name
        all_profiles = client.isolation_profile.list_isolation_profiles().to_list()
        if profile_name is not None:
            # Iterate over profiles to find the matching name
            for profile in all_profiles:
                if profile.get("name") == profile_name:
                    profiles = [profile]
                    break
            # Handle case where no rule with the given name is found
            if not profiles:
                module.fail_json(
                    msg="Failed to retrieve cloud browser profile : '%s'"
                    % (profile_name)
                )
        else:
            # Return all profiles if no specific name is provided
            profiles = all_profiles

    module.exit_json(changed=False, data=profiles)


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
