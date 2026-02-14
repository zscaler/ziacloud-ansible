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
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zia_cloud_app_control_rule_actions_info
short_description: "Get available Cloud App Control rule actions by rule type"
description:
  - "Retrieves granular actions supported for a specific Cloud App Control rule type and cloud applications."
  - "Equivalent to the Terraform C(zia_cloud_app_control_rule_actions) datasource."
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
  type:
    description:
      - The rule type for the Cloud App Control policy (e.g., C(web), C(WEBMAIL), C(STREAMING_MEDIA)).
    required: true
    type: str
  cloud_apps:
    description:
      - List of cloud application names to retrieve available actions for.
    required: true
    type: list
    elements: str
  action_prefixes:
    description:
      - Optional list of action prefixes to filter results.
      - Valid values include C(ALLOW), C(DENY), C(BLOCK), C(CAUTION), C(ISOLATE), C(ESC).
      - An underscore is automatically appended if not present.
      - Only actions starting with these prefixes are included in C(filtered_actions).
    required: false
    type: list
    elements: str
"""

EXAMPLES = r"""
- name: Get all available actions for WEBMAIL and AOL_MAIL
  zscaler.ziacloud.zia_cloud_app_control_rule_actions_info:
    provider: '{{ provider }}'
    type: "WEBMAIL"
    cloud_apps:
      - "AOL_MAIL"
  register: result

- name: Get available actions filtered by prefix
  zscaler.ziacloud.zia_cloud_app_control_rule_actions_info:
    provider: '{{ provider }}'
    type: "STREAMING_MEDIA"
    cloud_apps:
      - "DROPBOX"
    action_prefixes:
      - "ALLOW"
      - "BLOCK"
  register: result
"""

RETURN = r"""
available_actions:
  description:
    - List of all available actions for the specified cloud applications and rule type (includes ISOLATE actions).
  returned: always
  type: list
  elements: str
available_actions_without_isolate:
  description:
    - List of available actions excluding ISOLATE actions. Use for standard rules.
    - ISOLATE actions cannot be mixed with other actions.
  returned: always
  type: list
  elements: str
isolate_actions:
  description:
    - List of only ISOLATE actions. Use for Cloud Browser Isolation rules.
    - ISOLATE actions require cbi_profile configuration and cannot be mixed with other actions.
  returned: always
  type: list
  elements: str
filtered_actions:
  description:
    - List of actions filtered by C(action_prefixes). Only populated when C(action_prefixes) is specified.
  returned: always
  type: list
  elements: str
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    rule_type = module.params.get("type")
    cloud_apps = module.params.get("cloud_apps") or []
    action_prefixes = module.params.get("action_prefixes") or []

    if not cloud_apps:
        module.fail_json(msg="cloud_apps is required and must be a non-empty list.")

    client = ZIAClientHelper(module)
    actions, _unused, error = client.cloudappcontrol.list_available_actions(rule_type, cloud_apps)
    if error:
        module.fail_json(msg=f"Error retrieving available actions: {to_native(error)}")

    actions = list(actions) if actions else []

    # Separate ISOLATE actions from non-ISOLATE actions
    actions_without_isolate = [a for a in actions if not a.startswith("ISOLATE_")]
    isolate_actions = [a for a in actions if a.startswith("ISOLATE_")]

    # Filter by action_prefixes if specified
    filtered_actions = []
    if action_prefixes:
        prefixes = [p if p.endswith("_") else p + "_" for p in action_prefixes]
        for action in actions:
            for prefix in prefixes:
                if action.startswith(prefix):
                    filtered_actions.append(action)
                    break

    module.exit_json(
        changed=False,
        available_actions=actions,
        available_actions_without_isolate=actions_without_isolate,
        isolate_actions=isolate_actions,
        filtered_actions=filtered_actions,
    )


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            type=dict(type="str", required=True),
            cloud_apps=dict(type="list", elements="str", required=True),
            action_prefixes=dict(type="list", elements="str", required=False),
        )
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
