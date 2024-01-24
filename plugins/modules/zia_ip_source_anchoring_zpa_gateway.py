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
module: zia_ip_source_anchoring_zpa_gateway
short_description: "Manages ZPA Gateways within Zscaler Internet Access"
description:
  - "This module adds or updates a ZPA Gateway within Zscaler Internet Access (ZIA)."
  - "It allows for the configuration of server groups and application segments for source IP anchoring."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
  - Zscaler SDK Python (available on PyPI at https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.credentials_set
  - zscaler.ziacloud.fragments.state
options:
  id:
    description: "Unique identifier for the ZPA gateway."
    required: false
    type: int
  name:
    description: "Name of the ZPA gateway."
    required: true
    type: str
  description:
    description: "Additional details about the ZPA gateway."
    required: false
    type: str
  type:
    description: "Type of ZPA gateway. Choose 'ZPA' for Zscaler Internet Access or 'ECZPA' for Zscaler Cloud Connector."
    required: false
    type: str
    choices: [ZPA, ECZPA]
  zpa_server_group:
    description: "Server group associated with the ZPA gateway for source IP anchoring."
    required: true
    type: dict
    suboptions:
      external_id:
        description: "External identifier for the server group, managed outside of ZIA."
        required: true
        type: int
      name:
        description: "Name of the server group."
        required: true
        type: str
  zpa_app_segments:
    description: "Application segments associated with the server group. Optional if segments are predefined at the server group level."
    required: false
    type: list
    elements: dict
    suboptions:
      external_id:
        description: "External identifier for the application segment."
        required: true
        type: int
      name:
        description: "Name of the application segment."
        required: true
        type: str
"""
EXAMPLES = """
- name: Create or update a ZPA Gateway with application segments
  zscaler.ziacloud.zia_ip_source_anchoring_zpa_gateway:
    provider: '{{ zia_cloud }}'
    name: "ZPA_GW02"
    description: "ZPA Gateway for internal apps"
    type: "ZPA"
    zpa_server_group:
      external_id: 216196257331370454
      name: "Server Group for IP Anchoring"
    zpa_app_segments:
      - external_id: 216196257331370455
        name: "App Segment 1"
      - external_id: 216196257331370465
        name: "App Segment 2"

- name: Update a ZPA Gateway without specifying application segments
  zscaler.ziacloud.zia_ip_source_anchoring_zpa_gateway:
    provider: '{{ zia_cloud }}'
    name: "ZPA_GW02"
    description: "ZPA Gateway update"
    type: "ZPA"
    zpa_server_group:
      external_id: 216196257331370454
      name: "Updated Server Group"
"""
RETURN = """
# Returns information on the newly created ZPA Gateway.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_gateway(gateway):
    """
    Normalize zpa gateway data by ensuring consistent data types for external_id.
    """
    normalized = gateway.copy()

    # Remove 'id' from the top level
    normalized.pop("id", None)

    # Ensure external_id is a string for 'zpa_server_group'
    if "zpa_server_group" in normalized:
        sg = normalized["zpa_server_group"]
        normalized["zpa_server_group"] = {
            "external_id": str(sg.get("external_id")),
            "name": sg.get("name"),
        }

    # Ensure external_id is a string for each item in 'zpa_app_segments'
    if normalized.get("zpa_app_segments"):
        normalized["zpa_app_segments"] = [
            {"external_id": str(seg.get("external_id")), "name": seg.get("name")}
            for seg in normalized["zpa_app_segments"]
        ]

    return normalized


def compare_nested_structures(current, desired):
    """
    Compares nested structures (lists of dictionaries) for equality.
    Assumes that each dictionary has a unique identifier 'external_id'.
    """
    if isinstance(current, list) and isinstance(desired, list):
        current_sorted = sorted(current, key=lambda x: x.get("external_id"))
        desired_sorted = sorted(desired, key=lambda x: x.get("external_id"))
        return all(compare_dicts(c, d) for c, d in zip(current_sorted, desired_sorted))
    elif isinstance(current, dict) and isinstance(desired, dict):
        return compare_dicts(current, desired)
    return False


def compare_dicts(dict1, dict2):
    """
    Compares two dictionaries for equality, ignoring any 'id' keys.
    """
    if dict1.keys() != dict2.keys():
        return False
    for key in dict1:
        if key != "id" and dict1[key] != dict2[key]:
            return False
    return True


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    gateway = dict()
    params = [
        "id",
        "name",
        "description",
        "zpa_server_group",
        "zpa_app_segments",
    ]
    for param_name in params:
        gateway[param_name] = module.params.get(param_name, None)

    gateway_id = gateway.get("id", None)
    gateway_name = gateway.get("name", None)

    existing_gateway = None
    if gateway_id is not None:
        existing_gateway = client.zpa_gateway.get_gateway(gateway_id).to_dict()
    else:
        gateways = client.zpa_gateway.list_gateways().to_list()
        if gateway_name is not None:
            for gw in gateways:
                if gw.get("name", None) == gateway_name:
                    existing_gateway = gw
                    break

    # Normalize and compare existing and desired data
    desired_gateway = normalize_gateway(gateway)
    current_gateway = normalize_gateway(existing_gateway) if existing_gateway else {}

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in desired_gateway.items():
        current_value = current_gateway.get(key)

        # Skip comparison for 'zpa_app_segments' if it's not provided in the desired state
        if key == "zpa_app_segments" and value is None:
            continue

        # Special handling for 'type' attribute
        if key == "type" and current_value is None:
            if value != "ZPA":
                differences_detected = True
                module.warn(
                    f"Difference detected in {key}. Current: {current_value}, Desired: {value}"
                )

        # Custom comparison for nested fields
        elif key in ["zpa_server_group", "zpa_app_segments"]:
            if not compare_nested_structures(current_value, value):
                differences_detected = True
                module.warn(
                    f"Difference detected in {key}. Current: {current_value}, Desired: {value}"
                )

        # Regular comparison for other fields
        elif key not in fields_to_exclude and current_value != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_value}, Desired: {value}"
            )

    if existing_gateway is not None:
        id = existing_gateway.get("id")
        existing_gateway.update(desired_gateway)
        existing_gateway["id"] = id

    module.warn(f"Final payload being sent to SDK: {gateway}")
    if state == "present":
        if existing_gateway is not None:
            if differences_detected:
                """Update"""
                update_gateway = deleteNone(
                    dict(
                        gateway_id=existing_gateway.get("id"),
                        name=existing_gateway.get("name"),
                        description=existing_gateway.get("description"),
                        type=existing_gateway.get("type"),
                        zpa_server_group=existing_gateway.get("zpa_server_group"),
                        zpa_app_segments=existing_gateway.get("zpa_app_segments"),
                    )
                )
                updated_gateway_response = client.zpa_gateway.update_gateway(
                    **update_gateway
                )
                if updated_gateway_response is None:
                    module.fail_json(
                        msg="Failed to update gateway, received no response from SDK."
                    )

                # Use the updated gateway data directly in the module's response
                module.exit_json(changed=True, data=updated_gateway_response.to_dict())

            else:
                """No changes needed"""
                module.exit_json(
                    changed=False, data=existing_gateway, msg="No changes detected."
                )
        else:
            module.warn("Creating new rule as no existing rule found")
            """Create"""
            create_gateway = deleteNone(
                dict(
                    name=gateway.get("name"),
                    description=gateway.get("description"),
                    type=gateway.get("type"),
                    zpa_server_group=gateway.get("zpa_server_group"),
                    zpa_app_segments=gateway.get("zpa_app_segments"),
                )
            )
            module.warn("Payload for SDK: {}".format(create_gateway))
            new_gateway = client.zpa_gateway.add_gateway(**create_gateway).to_dict()
            module.exit_json(changed=True, data=new_gateway)
    elif (
        state == "absent"
        and existing_gateway is not None
        and existing_gateway.get("id") is not None
    ):
        code = client.zpa_gateway.delete_gateway(existing_gateway.get("id"))
        if code > 299:
            module.exit_json(changed=False, data=None)
        module.exit_json(changed=True, data=existing_gateway)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()

    # Define the spec for a dictionary with external_id and name
    external_id_name_dict_spec = dict(
        external_id=dict(type="int", required=True),
        name=dict(type="str", required=True),
    )

    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        zpa_server_group=dict(
            type="dict",
            options=external_id_name_dict_spec,
            required=True,
        ),
        zpa_app_segments=dict(
            type="list",
            elements="dict",
            options=external_id_name_dict_spec,
            required=False,
        ),
        type=dict(
            type="str",
            required=False,
            default="ZPA",
            choices=["ZPA", "ECZPA"],
        ),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
