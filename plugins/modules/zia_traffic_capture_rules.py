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
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zia_traffic_capture_rules
short_description: "Manages ZIA Traffic Capture policy rules"
description:
  - "Creates, updates, or deletes Traffic Capture policy rules."
  - "Traffic Capture rules control which traffic is captured for inspection."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
    - Use C(id) or C(name) to reference an existing rule for update/delete.
    - Deletion of predefined rules is not allowed.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description:
      - The unique identifier for the Traffic Capture rule.
      - Used to reference an existing rule for update or delete.
    required: false
    type: int
  name:
    description:
      - Name of the Traffic Capture policy rule.
      - Required for create.
    required: true
    type: str
  description:
    description:
      - Additional information about the rule.
      - Maximum 10240 characters.
    required: false
    type: str
  order:
    description:
      - Rule order number. If omitted, the rule will be added to the end of the rule set.
    required: false
    type: int
  rank:
    description:
      - Admin rank of the rule (0-7).
    required: false
    default: 7
    type: int
  action:
    description:
      - The action to be enforced when the traffic matches the rule criteria.
    required: false
    type: str
    choices:
      - CAPTURE
      - SKIP
  rule_state:
    description:
      - Determines whether the rule is enabled or disabled.
    required: false
    type: str
    choices:
      - ENABLED
      - DISABLED
  src_ips:
    description:
      - User-defined source IP addresses for which the rule is applicable.
    required: false
    type: list
    elements: str
  dest_addresses:
    description:
      - Destination addresses. Supports IPv4, FQDNs, or wildcard FQDNs.
    required: false
    type: list
    elements: str
  dest_ip_categories:
    description:
      - IP address categories of destination.
    required: false
    type: list
    elements: str
  nw_applications:
    description:
      - Network application names.
    required: false
    type: list
    elements: str
  default_rule:
    description:
      - If set to true, the default rule is applied.
    required: false
    type: bool
  predefined:
    description:
      - If set to true, a predefined rule is applied.
    required: false
    type: bool
  txn_size_limit:
    description:
      - The maximum size of traffic to capture per connection.
    required: false
    type: str
    choices:
      - NONE
      - UNLIMITED
      - THIRTY_TWO_KB
      - TWO_FIFTY_SIX_KB
      - TWO_MB
      - FOUR_MB
      - THIRTY_TWO_MB
      - SIXTY_FOUR_MB
  txn_sampling:
    description:
      - The percentage of connections sampled for capturing each time the rule is triggered.
    required: false
    type: str
    choices:
      - NONE
      - ONE_PERCENT
      - TWO_PERCENT
      - FIVE_PERCENT
      - TEN_PERCENT
      - TWENTY_FIVE_PERCENT
      - HUNDRED_PERCENT
  locations:
    description:
      - List of location IDs for which the rule must be applied.
    required: false
    type: list
    elements: int
  location_groups:
    description:
      - List of location group IDs.
    required: false
    type: list
    elements: int
  users:
    description:
      - List of user IDs for which the rule must be applied.
    required: false
    type: list
    elements: int
  groups:
    description:
      - List of group IDs for which the rule must be applied.
    required: false
    type: list
    elements: int
  departments:
    description:
      - List of department IDs for which the rule must be applied.
    required: false
    type: list
    elements: int
  time_windows:
    description:
      - The time interval in which the rule applies.
    required: false
    type: list
    elements: int
  labels:
    description:
      - List of label IDs applicable to the rule.
    required: false
    type: list
    elements: int
  device_groups:
    description:
      - List of device group IDs (for Zscaler Client Connector managed devices).
    required: false
    type: list
    elements: int
  devices:
    description:
      - List of device IDs for which the rule must be applied.
    required: false
    type: list
    elements: int
  src_ip_groups:
    description:
      - List of source IP group IDs.
    required: false
    type: list
    elements: int
  dest_ip_groups:
    description:
      - List of destination IP group IDs.
    required: false
    type: list
    elements: int
  app_service_groups:
    description:
      - List of application service group IDs.
    required: false
    type: list
    elements: int
  nw_application_groups:
    description:
      - List of network application group IDs.
    required: false
    type: list
    elements: int
  nw_service_groups:
    description:
      - List of network service group IDs.
    required: false
    type: list
    elements: int
  nw_services:
    description:
      - List of network service IDs.
    required: false
    type: list
    elements: int
  workload_groups:
    description:
      - List of preconfigured workload group IDs.
    required: false
    type: list
    elements: int
  dest_countries:
    description:
      - Destination countries. Provide ISO3166 Alpha2 codes (e.g., US, BR).
    required: false
    type: list
    elements: str
  source_countries:
    description:
      - Source countries. Provide ISO3166 Alpha2 codes.
    required: false
    type: list
    elements: str
  exclude_src_countries:
    description:
      - Indicates whether source countries are excluded from the rule.
    required: false
    type: bool
  device_trust_levels:
    description:
      - Device trust levels for the rule application.
    required: false
    type: list
    elements: str
    choices:
      - ANY
      - UNKNOWN_DEVICETRUSTLEVEL
      - LOW_TRUST
      - MEDIUM_TRUST
      - HIGH_TRUST
"""

EXAMPLES = r"""
- name: Create a Traffic Capture rule
  zscaler.ziacloud.zia_traffic_capture_rules:
    provider: '{{ provider }}'
    name: "Capture Rule 01"
    description: "Captures traffic for inspection"
    order: 1
    action: CAPTURE
    rule_state: ENABLED
    src_ips:
      - "192.168.1.0/24"
    dest_addresses:
      - "*.example.com"
    txn_sampling: TEN_PERCENT

- name: Update a Traffic Capture rule by ID
  zscaler.ziacloud.zia_traffic_capture_rules:
    provider: '{{ provider }}'
    id: 1254654
    name: "Capture Rule 01 Updated"
    description: "Updated description"

- name: Delete a Traffic Capture rule
  zscaler.ziacloud.zia_traffic_capture_rules:
    provider: '{{ provider }}'
    id: 1254654
    state: absent
"""

RETURN = r"""
data:
  description: The Traffic Capture rule resource record.
  returned: on success
  type: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
    validate_iso3166_alpha2,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_rule(rule):
    """Normalize rule data by removing computed values."""
    if not rule:
        return {}
    return rule.copy()


def core(module):
    state = module.params.get("state", "present")
    client = ZIAClientHelper(module)

    id_spec = dict(type="list", elements="int", required=False)
    params = [
        "id",
        "name",
        "order",
        "rank",
        "action",
        "rule_state",
        "description",
        "src_ips",
        "dest_addresses",
        "dest_ip_categories",
        "nw_applications",
        "default_rule",
        "predefined",
        "txn_size_limit",
        "txn_sampling",
        "locations",
        "location_groups",
        "users",
        "groups",
        "departments",
        "time_windows",
        "labels",
        "device_groups",
        "devices",
        "src_ip_groups",
        "dest_ip_groups",
        "app_service_groups",
        "nw_application_groups",
        "nw_service_groups",
        "nw_services",
        "workload_groups",
        "dest_countries",
        "source_countries",
        "exclude_src_countries",
        "device_trust_levels",
    ]

    rule = {param: module.params.get(param) for param in params}

    # Validate and format country codes
    source_countries = rule.get("source_countries")
    if source_countries:
        validated = []
        for code in source_countries:
            if validate_iso3166_alpha2(code):
                validated.append(f"COUNTRY_{code}")
            else:
                module.fail_json(msg=f"Invalid source country code '{code}'. Must be ISO3166 Alpha2.")
        rule["source_countries"] = validated

    dest_countries = rule.get("dest_countries")
    if dest_countries:
        validated = []
        for code in dest_countries:
            if validate_iso3166_alpha2(code):
                validated.append(f"COUNTRY_{code}")
            else:
                module.fail_json(msg=f"Invalid destination country code '{code}'. Must be ISO3166 Alpha2.")
        rule["dest_countries"] = validated

    if rule.get("exclude_src_countries") and not rule.get("source_countries"):
        module.fail_json(msg="When 'exclude_src_countries' is True, 'source_countries' must be specified.")

    rule_id = rule.get("id")
    rule_name = rule.get("name")

    existing_rule = None
    if rule_id is not None:
        result, _unused, error = client.traffic_capture.get_rule(rule_id)
        if error:
            module.fail_json(msg=f"Error fetching Traffic Capture rule with id {rule_id}: {to_native(error)}")
        if result:
            existing_rule = result.as_dict()
    else:
        result, _unused, error = client.traffic_capture.list_rules()
        if error:
            module.fail_json(msg=f"Error listing Traffic Capture rules: {to_native(error)}")
        if result:
            for r in result:
                if r.name == rule_name:
                    existing_rule = r.as_dict()
                    break

    # Prevent deletion of predefined rules
    if state == "absent" and existing_rule:
        if existing_rule.get("predefined", False):
            module.exit_json(
                changed=False,
                msg="Deletion of predefined rule is not allowed.",
            )

    desired_rule = normalize_rule(rule)
    current_rule = normalize_rule(existing_rule) if existing_rule else {}

    def preprocess_rule(rule_dict):
        """Preprocess rule attributes for comparison."""
        processed = rule_dict.copy()
        id_list_params = [
            "locations",
            "location_groups",
            "users",
            "groups",
            "departments",
            "time_windows",
            "labels",
            "device_groups",
            "devices",
            "src_ip_groups",
            "dest_ip_groups",
            "app_service_groups",
            "nw_application_groups",
            "nw_service_groups",
            "nw_services",
            "workload_groups",
        ]
        for attr in id_list_params:
            if attr in processed and processed[attr] is not None:
                if isinstance(processed[attr], list):
                    if all(isinstance(item, dict) and "id" in item for item in processed[attr]):
                        processed[attr] = sorted([item["id"] for item in processed[attr]])
                    elif all(isinstance(item, int) for item in processed[attr]):
                        processed[attr] = sorted(processed[attr])
        list_params = [
            "src_ips",
            "dest_addresses",
            "dest_ip_categories",
            "nw_applications",
            "dest_countries",
            "source_countries",
            "device_trust_levels",
        ]
        for attr in list_params:
            if attr in processed and isinstance(processed.get(attr), list):
                processed[attr] = sorted(processed[attr]) if processed[attr] else []
        return processed

    desired_processed = preprocess_rule(desired_rule)
    current_processed = preprocess_rule(current_rule)

    list_attributes = [
        "locations",
        "location_groups",
        "users",
        "groups",
        "departments",
        "time_windows",
        "labels",
        "device_groups",
        "devices",
        "src_ip_groups",
        "dest_ip_groups",
        "app_service_groups",
        "nw_application_groups",
        "nw_service_groups",
        "nw_services",
        "workload_groups",
        "src_ips",
        "dest_addresses",
        "dest_ip_categories",
        "nw_applications",
        "dest_countries",
        "source_countries",
        "device_trust_levels",
    ]

    differences_detected = False
    for key in params:
        desired_value = desired_processed.get(key)
        current_value = current_processed.get(key)

        if key == "id" and desired_value is None and current_value is not None:
            continue

        if key in list_attributes:
            if desired_value in (None, []) and current_value in (None, []):
                continue
            desired_value = desired_value if desired_value is not None else []
            current_value = current_value if current_value is not None else []

        if module.params.get("exclude_src_countries") is None and key == "exclude_src_countries":
            continue
        if key == "rule_state":
            current_value = current_rule.get("state")

        if isinstance(desired_value, list) and isinstance(current_value, list):
            if all(isinstance(x, int) for x in desired_value) and all(isinstance(x, int) for x in current_value):
                desired_value = sorted(desired_value)
                current_value = sorted(current_value)

        if current_value != desired_value:
            differences_detected = True
            break

    if module.check_mode:
        module.exit_json(changed=bool((state == "present" and (not existing_rule or differences_detected)) or (state == "absent" and existing_rule)))

    if state == "present":
        if existing_rule:
            if differences_detected:
                update_data = deleteNone(
                    {
                        "name": desired_rule.get("name"),
                        "order": desired_rule.get("order"),
                        "rank": desired_rule.get("rank"),
                        "action": desired_rule.get("action"),
                        "state": desired_rule.get("rule_state"),
                        "description": desired_rule.get("description"),
                        "src_ips": desired_rule.get("src_ips"),
                        "dest_addresses": desired_rule.get("dest_addresses"),
                        "dest_ip_categories": desired_rule.get("dest_ip_categories"),
                        "nw_applications": desired_rule.get("nw_applications"),
                        "default_rule": desired_rule.get("default_rule"),
                        "predefined": desired_rule.get("predefined"),
                        "txn_size_limit": desired_rule.get("txn_size_limit"),
                        "txn_sampling": desired_rule.get("txn_sampling"),
                        "locations": desired_rule.get("locations"),
                        "location_groups": desired_rule.get("location_groups"),
                        "users": desired_rule.get("users"),
                        "groups": desired_rule.get("groups"),
                        "departments": desired_rule.get("departments"),
                        "time_windows": desired_rule.get("time_windows"),
                        "labels": desired_rule.get("labels"),
                        "device_groups": desired_rule.get("device_groups"),
                        "devices": desired_rule.get("devices"),
                        "src_ip_groups": desired_rule.get("src_ip_groups"),
                        "dest_ip_groups": desired_rule.get("dest_ip_groups"),
                        "app_service_groups": desired_rule.get("app_service_groups"),
                        "nw_application_groups": desired_rule.get("nw_application_groups"),
                        "nw_service_groups": desired_rule.get("nw_service_groups"),
                        "nw_services": desired_rule.get("nw_services"),
                        "workload_groups": desired_rule.get("workload_groups"),
                        "dest_countries": desired_rule.get("dest_countries"),
                        "source_countries": desired_rule.get("source_countries"),
                        "exclude_src_countries": desired_rule.get("exclude_src_countries"),
                        "device_trust_levels": desired_rule.get("device_trust_levels"),
                    }
                )
                updated_rule, _unused, error = client.traffic_capture.update_rule(existing_rule.get("id"), **update_data)
                if error:
                    module.fail_json(msg=f"Error updating Traffic Capture rule: {to_native(error)}")
                module.exit_json(changed=True, data=updated_rule.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule)
        else:
            # Resolve order if not provided - append to end
            order = desired_rule.get("order")
            if order is None:
                result, _unused, error = client.traffic_capture.list_rules()
                if error:
                    module.fail_json(msg=f"Error listing rules to determine order: {to_native(error)}")
                max_order = 0
                if result:
                    for r in result:
                        if getattr(r, "order", 0) and r.order > max_order:
                            max_order = r.order
                order = max_order + 1
                desired_rule["order"] = order

            create_data = deleteNone(
                {
                    "name": desired_rule.get("name"),
                    "order": desired_rule.get("order"),
                    "rank": desired_rule.get("rank") or 7,
                    "action": desired_rule.get("action"),
                    "state": desired_rule.get("rule_state"),
                    "description": desired_rule.get("description"),
                    "src_ips": desired_rule.get("src_ips"),
                    "dest_addresses": desired_rule.get("dest_addresses"),
                    "dest_ip_categories": desired_rule.get("dest_ip_categories"),
                    "nw_applications": desired_rule.get("nw_applications"),
                    "default_rule": desired_rule.get("default_rule"),
                    "predefined": desired_rule.get("predefined"),
                    "txn_size_limit": desired_rule.get("txn_size_limit"),
                    "txn_sampling": desired_rule.get("txn_sampling"),
                    "locations": desired_rule.get("locations"),
                    "location_groups": desired_rule.get("location_groups"),
                    "users": desired_rule.get("users"),
                    "groups": desired_rule.get("groups"),
                    "departments": desired_rule.get("departments"),
                    "time_windows": desired_rule.get("time_windows"),
                    "labels": desired_rule.get("labels"),
                    "device_groups": desired_rule.get("device_groups"),
                    "devices": desired_rule.get("devices"),
                    "src_ip_groups": desired_rule.get("src_ip_groups"),
                    "dest_ip_groups": desired_rule.get("dest_ip_groups"),
                    "app_service_groups": desired_rule.get("app_service_groups"),
                    "nw_application_groups": desired_rule.get("nw_application_groups"),
                    "nw_service_groups": desired_rule.get("nw_service_groups"),
                    "nw_services": desired_rule.get("nw_services"),
                    "workload_groups": desired_rule.get("workload_groups"),
                    "dest_countries": desired_rule.get("dest_countries"),
                    "source_countries": desired_rule.get("source_countries"),
                    "exclude_src_countries": desired_rule.get("exclude_src_countries"),
                    "device_trust_levels": desired_rule.get("device_trust_levels"),
                }
            )
            new_rule, _unused, error = client.traffic_capture.add_rule(**create_data)
            if error:
                module.fail_json(msg=f"Error creating Traffic Capture rule: {to_native(error)}")
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            _unused, _unused, error = client.traffic_capture.delete_rule(existing_rule.get("id"))
            if error:
                module.fail_json(msg=f"Error deleting Traffic Capture rule: {to_native(error)}")
            module.exit_json(changed=True, data=existing_rule)
        else:
            module.exit_json(changed=False, data={})

    module.exit_json(changed=False, data={})


def main():
    id_spec = dict(type="list", elements="int", required=False)
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        order=dict(type="int", required=False),
        rank=dict(type="int", required=False, default=7),
        action=dict(
            type="str",
            required=False,
            choices=["CAPTURE", "SKIP"],
        ),
        rule_state=dict(
            type="str",
            required=False,
            choices=["ENABLED", "DISABLED"],
        ),
        src_ips=dict(type="list", elements="str", required=False),
        dest_addresses=dict(type="list", elements="str", required=False),
        dest_ip_categories=dict(type="list", elements="str", required=False),
        nw_applications=dict(type="list", elements="str", required=False),
        default_rule=dict(type="bool", required=False),
        predefined=dict(type="bool", required=False),
        txn_size_limit=dict(
            type="str",
            required=False,
            choices=[
                "NONE",
                "UNLIMITED",
                "THIRTY_TWO_KB",
                "TWO_FIFTY_SIX_KB",
                "TWO_MB",
                "FOUR_MB",
                "THIRTY_TWO_MB",
                "SIXTY_FOUR_MB",
            ],
        ),
        txn_sampling=dict(
            type="str",
            required=False,
            choices=[
                "NONE",
                "ONE_PERCENT",
                "TWO_PERCENT",
                "FIVE_PERCENT",
                "TEN_PERCENT",
                "TWENTY_FIVE_PERCENT",
                "HUNDRED_PERCENT",
            ],
        ),
        locations=id_spec,
        location_groups=id_spec,
        users=id_spec,
        groups=id_spec,
        departments=id_spec,
        time_windows=id_spec,
        labels=id_spec,
        device_groups=id_spec,
        devices=id_spec,
        src_ip_groups=id_spec,
        dest_ip_groups=id_spec,
        app_service_groups=id_spec,
        nw_application_groups=id_spec,
        nw_service_groups=id_spec,
        nw_services=id_spec,
        workload_groups=id_spec,
        dest_countries=dict(type="list", elements="str", required=False),
        source_countries=dict(type="list", elements="str", required=False),
        exclude_src_countries=dict(type="bool", required=False),
        device_trust_levels=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "ANY",
                "UNKNOWN_DEVICETRUSTLEVEL",
                "LOW_TRUST",
                "MEDIUM_TRUST",
                "HIGH_TRUST",
            ],
        ),
        state=dict(
            type="str",
            choices=["present", "absent"],
            default="present",
        ),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
