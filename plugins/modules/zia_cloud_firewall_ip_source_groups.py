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

DOCUMENTATION = r"""
---
module: zia_cloud_firewall_ip_source_groups
short_description: "Cloud Firewall IP source groups"
description:
  - "List of Cloud Firewall IP source groups"
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider

  - zscaler.ziacloud.fragments.state
options:
  id:
    description: "A unique identifier of the source IP address group"
    required: false
    type: str
  name:
    description: "The name of the source IP address group"
    required: true
    type: str
  description:
    description: "The description of the source IP address group"
    required: true
    type: str
  ip_addresses:
    description: "Source IP addresses added to the group"
    type: list
    elements: str
    required: true
"""

EXAMPLES = r"""

- name: Create/Update/Delete ip source group.
  zscaler.ziacloud.zia_cloud_firewall_ip_source_groups:
    provider: '{{ provider }}'
    name: "Example"
    description: "Example"
    ip_addresses:
        - 192.168.1.1
        - 192.168.1.2
        - 192.168.1.3
"""

RETURN = r"""
# The newly created ip source group resource record.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_ip_group(group):
    """
    Normalize ip source group data by setting computed values.
    """
    normalized = group.copy()

    computed_values = [
        "id",
        "name",
        "description",
        "is_non_editable",
        "ip_addresses",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    source_group = dict()
    params = [
        "id",
        "name",
        "description",
        "ip_addresses",
    ]
    for param_name in params:
        source_group[param_name] = module.params.get(param_name, None)
    group_id = source_group.get("id", None)
    group_name = source_group.get("name", None)

    existing_src_ip_group = None
    if group_id is not None:
        existing_src_ip_group = client.firewall.get_ip_source_group(group_id).to_dict()
    else:
        source_groups = client.firewall.list_ip_source_groups().to_list()
        if group_name is not None:
            for ip in source_groups:
                if ip.get("name", None) == group_name:
                    existing_src_ip_group = ip
                    break

    # Normalize and compare existing and desired data
    normalized_group = normalize_ip_group(source_group)
    normalized_existing_group = (
        normalize_ip_group(existing_src_ip_group) if existing_src_ip_group else {}
    )

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in normalized_group.items():
        if key not in fields_to_exclude and normalized_existing_group.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing_group.get(key)}, Desired: {value}"
            )

    if existing_src_ip_group is not None:
        id = existing_src_ip_group.get("id")
        existing_src_ip_group.update(normalized_group)
        existing_src_ip_group["id"] = id

    if state == "present":
        if existing_src_ip_group is not None:
            if differences_detected:
                """Update"""
                existing_src_ip_group = client.firewall.update_ip_source_group(
                    group_id=existing_src_ip_group.get("id", ""),
                    name=existing_src_ip_group.get("name", ""),
                    description=existing_src_ip_group.get("description", ""),
                    ip_addresses=existing_src_ip_group.get("ip_addresses", ""),
                ).to_dict()
                module.exit_json(changed=True, data=existing_src_ip_group)
        else:
            """Create"""
            source_group = client.firewall.add_ip_source_group(
                name=source_group.get("name", ""),
                description=source_group.get("description", ""),
                ip_addresses=source_group.get("ip_addresses", ""),
            ).to_dict()
            module.exit_json(changed=False, data=source_group)
    elif state == "absent":
        if existing_src_ip_group is not None:
            code = client.firewall.delete_ip_source_group(
                existing_src_ip_group.get("id")
            )
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_src_ip_group)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        ip_addresses=dict(type="list", elements="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
