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
module: zia_dlp_idm_profile_facts
short_description: "Get IDM template information"
description:
  - "Get IDM template information for the specified ID or Name"
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
    - zscaler.ziacloud.fragments.credentials_set
    - zscaler.ziacloud.fragments.provider
options:
  profile_id:
    description: "The identifier (1-64) for the IDM template (i.e., IDM profile) that is unique within the organization"
    required: false
    type: int
  profile_name:
    type: str
    required: false
    description:
      - The IDM template name, which is unique per Index Tool.
"""

EXAMPLES = """
- name: Gets all list of DLP IDM Profiles
  zscaler.ziacloud.zia_dlp_idm_profile_facts:

- name: Gets a list of  DLP IDM Profiles by name
  zscaler.ziacloud.zia_dlp_idm_profile_facts:
    name: "IDM_PROFILE_TEMPLATE"
"""

RETURN = """
# Returns information about specific DLP IDM Profiles.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    profile_id = module.params.get("profile_id", None)
    profile_name = module.params.get("template_name", None)
    client = ZIAClientHelper(module)
    idm_profiles = []
    if profile_id is not None:
        profile = client.dlp.get_dlp_idm_profiles(profile_id).to_dict()
        idm_profiles = [profile]
    else:
        idm_profiles = client.dlp.list_dlp_idm_profiles().to_list()
        if profile_name is not None:
            profile = None
            for idm in idm_profiles:
                if idm.get("profile_name", None) == profile_name:
                    profile = idm
                    break
            if profile is None:
                module.fail_json(
                    msg="Failed to retrieve dlp idm profile: '%s'" % (profile_name)
                )
            idm_profiles = [profile]
    module.exit_json(changed=False, data=idm_profiles)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        profile_name=dict(type="str", required=False),
        profile_id=dict(type="int", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
