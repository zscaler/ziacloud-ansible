#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, Zscaler Technology Alliances <zscaler-partner-labs@z-bd.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_activation_status_info
short_description: "Gets the activation status."
description: "Gets the activation status for the saved configuration changes."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
options:
  username:
    description: "Username of admin user that is provisioned"
    required: true
    type: str
  password:
    description: "Password of the admin user"
    required: true
    type: str
  api_key:
    description: "The obfuscated form of the API key"
    required: true
    type: str
  base_url:
    description: "The host and basePath for the cloud services API"
    required: true
    type: str
  status:
    description:
        - Organization Policy Edit/Update Activation status
    required: false
    type: str
    choices:
        - "ACTIVE"
        - "PENDING"
        - "INPROGRESS"
"""

EXAMPLES = """
- name: Gets the activation status for the saved configuration changes
  zscaler.ziacloud.zia_activation_status:
    status: "ACTIVE"
"""

RETURN = """
# Gets the activation status for the saved configuration changes.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    zia_argument_spec,
)
from zscaler import ZIA

def core(module: AnsibleModule):
    activation_status = module.params.get("status", None)
    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )

    current_activation_status = client.config.activate()

    # If specific status provided, check if it matches the current activation status
    if activation_status:
        if current_activation_status == activation_status:
            module.exit_json(changed=False, data=current_activation_status, status_matches=True)
        else:
            module.exit_json(changed=False, data=current_activation_status, status_matches=False, msg=f"Provided status '{activation_status}' does not match the current activation status '{current_activation_status}'")
    else:
        module.exit_json(changed=False, data=current_activation_status)

def main():
    argument_spec = zia_argument_spec()
    argument_spec.update(
        status=dict(type="str", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())

if __name__ == "__main__":
    main()
