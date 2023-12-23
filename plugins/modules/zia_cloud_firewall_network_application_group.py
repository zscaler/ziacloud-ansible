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
module: zia_cloud_firewall_network_application_group
short_description: "Cloud Firewall Network Application Group"
description:
  - "Creates a new custom network application group."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.credentials_set
  - zscaler.ziacloud.fragments.state
options:
  id:
    description: "A unique identifier of the network application groups"
    required: false
    type: str
  name:
    description: "The name of the network application groups"
    required: true
    type: str
  network_applications:
    description: "List of applications in the network application group"
    type: list
    elements: str
    required: true
"""

EXAMPLES = """
- name: Create/Update/Delete network application group.
  zscaler.ziacloud.zia_cloud_firewall_network_application_group:
    name: "sampleNetworkApplicationGroup"
    network_applications:
        - 'YAMMER'
        - 'OFFICE365'
        - 'SKYPE_FOR_BUSINESS'
        - 'OUTLOOK'
        - 'SHAREPOINT'
        - 'SHAREPOINT_ADMIN'
        - 'SHAREPOINT_BLOG'
        - 'SHAREPOINT_CALENDAR'
        - 'SHAREPOINT_DOCUMENT'
        - 'SHAREPOINT_ONLINE'
        - 'ONEDRIVE'
"""

RETURN = """
# The newly created network application group resource record.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_app_group(group):
    """
    Normalize network application group data by setting computed values.
    """
    normalized = group.copy()

    computed_values = [
        "id",
        "name",
        "description",
        "network_applications",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    app_group = dict()
    params = [
        "id",
        "name",
        "description",
        "network_applications",
    ]
    for param_name in params:
        app_group[param_name] = module.params.get(param_name, None)
    group_id = app_group.get("id", None)
    group_name = app_group.get("name", None)
    existing_app_group = None
    if group_id is not None:
        existing_app_group = client.firewall.get_network_app_group(group_id).to_dict()
    else:
        app_groups = client.firewall.list_network_app_groups().to_list()
        if group_name is not None:
            for app in app_groups:
                if app.get("name", None) == group_name:
                    existing_app_group = app
                    break

    # Normalize and compare existing and desired data
    normalized_group = normalize_app_group(app_group)
    normalized_existing_group = (
        normalize_app_group(existing_app_group) if existing_app_group else {}
    )

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in normalized_group.items():
        if key not in fields_to_exclude and normalized_existing_group.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing_group.get(key)}, Desired: {value}"
            )

    if existing_app_group is not None:
        id = existing_app_group.get("id")
        existing_app_group.update(normalized_group)
        existing_app_group["id"] = id

    if state == "present":
        if existing_app_group is not None:
            if differences_detected:
                """Update"""
                existing_app_group = client.firewall.update_network_app_group(
                    group_id=existing_app_group.get("id", ""),
                    name=existing_app_group.get("name", ""),
                    network_applications=existing_app_group.get(
                        "network_applications", ""
                    ),
                    description=existing_app_group.get("description", ""),
                ).to_dict()
                module.exit_json(changed=True, data=existing_app_group)
        else:
            """Create"""
            app_group = client.firewall.add_network_app_group(
                name=app_group.get("name", ""),
                network_applications=app_group.get("network_applications", ""),
                description=app_group.get("description", ""),
            ).to_dict()
            module.exit_json(changed=False, data=app_group)
    elif state == "absent":
        if existing_app_group is not None:
            code = client.firewall.delete_network_app_group(
                existing_app_group.get("id")
            )
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_app_group)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        network_applications=dict(type="list", elements="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
