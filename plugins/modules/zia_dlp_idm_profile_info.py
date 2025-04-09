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
module: zia_dlp_idm_profile_info
short_description: "Get IDM template information"
description:
  - "Get IDM template information for the specified ID or Name"
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
  profile_id:
    description: "The identifier (1-64) for the IDM template (i.e., IDM profile) that is unique within the organization"
    type: int
    required: false
  profile_name:
    type: str
    required: false
    description:
      - The IDM template name, which is unique per Index Tool.
"""

EXAMPLES = r"""
- name: Gets all list of DLP IDM Profiles
  zscaler.ziacloud.zia_dlp_idm_profile_info:
    provider: '{{ provider }}'

- name: Gets a list of  DLP IDM Profiles by name
  zscaler.ziacloud.zia_dlp_idm_profile_info:
    provider: '{{ provider }}'
    name: "IDM_PROFILE_TEMPLATE"
"""

RETURN = r"""
idm_profiles:
  description: List of DLP IDM profiles retrieved from the Zscaler system.
  returned: always
  type: list
  elements: dict
  contains:
    idm_client:
      description: Object containing the IDM client details.
      type: dict
      returned: always
      contains:
        id:
          description: Unique identifier for the IDM client.
          type: int
          returned: always
          sample: 38316
        name:
          description: Name of the IDM client.
          type: str
          returned: always
          sample: "ZS_DLP_IDX01"
    last_modified_time:
      description: The UNIX timestamp when the profile was last modified.
      type: int
      returned: always
      sample: 1702106392
    modified_by:
      description: Object containing details about the user who last modified the profile.
      type: dict
      returned: always
      contains:
        id:
          description: Unique identifier of the user.
          type: int
          returned: always
          sample: 44772836
        name:
          description: Name of the user.
          type: str
          returned: always
          sample: "admin@44772833.zscalertwo.net"
    num_documents:
      description: Number of documents associated with the profile.
      type: int
      returned: always
      sample: 1
    port:
      description: The network port used by the IDM client.
      type: int
      returned: always
      sample: 0
    profile_id:
      description: Unique identifier for the IDM profile.
      type: int
      returned: always
      sample: 1
    profile_name:
      description: Name of the IDM profile.
      type: str
      returned: always
      sample: "BD_IDM_TEMPLATE01"
    profile_type:
      description: Type of the IDM profile.
      type: str
      returned: always
      sample: "LOCAL"
    schedule_day:
      description: The day of the week when the profile is scheduled to run.
      type: int
      returned: always
      sample: 0
    schedule_disabled:
      description: Boolean flag indicating whether the schedule is disabled.
      type: bool
      returned: always
      sample: false
    schedule_time:
      description: The time of day when the profile is scheduled to run.
      type: int
      returned: always
      sample: 0
    schedule_type:
      description: The type of scheduling used for the IDM profile.
      type: str
      returned: always
      sample: "NONE"
    upload_status:
      description: Status of the IDM profile upload.
      type: str
      returned: always
      sample: "IDM_PROF_UPLOAD_COMPLETED"
    version:
      description: Version number of the IDM profile.
      type: int
      returned: always
      sample: 1
    volume_of_documents:
      description: The volume of documents associated with the profile.
      type: int
      returned: always
      sample: 153025
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    profile_id = module.params.get("profile_id")
    name = module.params.get("profile_name")
    client = ZIAClientHelper(module)
    idm_profiles = []

    if profile_id:
        result, _, error = client.dlp_resources.get_dlp_idm_profiles(profile_id)
        if error:
            module.fail_json(msg=f"Error retrieving IDM profile ID {profile_id}: {to_native(error)}")
        idm_profiles = [result.as_dict()]
    elif name:
        result, _, error = client.dlp_resources.list_dlp_idm_profiles(query_params={"search": name})
        if error:
            module.fail_json(msg=f"Error searching IDM profiles: {to_native(error)}")
        matching = [p.as_dict() for p in result if p.name == name]
        if not matching:
            module.fail_json(msg=f"No IDM profile found with name '{name}'")
        idm_profiles = matching
    else:
        result, _, error = client.dlp_resources.list_dlp_idm_profiles()
        if error:
            module.fail_json(msg=f"Error listing IDM profiles: {to_native(error)}")
        idm_profiles = [p.as_dict() for p in result]

    module.exit_json(changed=False, idm_profiles=idm_profiles)


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
