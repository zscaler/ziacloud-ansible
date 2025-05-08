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
module: zia_bandwidth_control_rules
short_description: "Adds a new Bandwidth Control policy rule"
description: "Adds a new Bandwidth Control policy rule"
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description: "Unique identifier for the Bandwidth Control Rule"
    required: false
    type: int
  name:
    description: "Name of the Bandwidth Control Rule"
    required: true
    type: str
  description:
    description: "Additional information about the rule"
    required: false
    type: str
  order:
    description: "Rule order number of the Bandwidth Control Rule"
    required: false
    type: int
  rank:
    description: "Admin rank of the Bandwidth Control Rule"
    required: false
    default: 7
    type: int
  enabled:
    description:
        - Determines whether the Bandwidth Control Rule is enabled or disabled
    required: false
    type: bool
  max_bandwidth:
    description:
        - The maximum percentage of a location's bandwidth to be guaranteed for each selected bandwidth class.
        - This percentage includes bandwidth for uploads and downloads.
    required: false
    type: int
  min_bandwidth:
    description:
        - The minimum percentage of a location's bandwidth you want to be guaranteed for each selected bandwidth class.
        - This percentage includes bandwidth for uploads and downloads.
    required: false
    type: int
  bandwidth_classes:
    description:
        - The bandwidth classes to which you want to apply this rule.
        - You first must add URLs or cloud applications to predefined or custom bandwidth classes.
    type: list
    elements: int
    required: false
  labels:
    description:
        - The URL Filtering rule label. Rule labels allow you to logically group your organization policy rules.
        - Policy rules that are not associated with a rule label are grouped under the Untagged label.
    type: list
    elements: int
    required: false
  locations:
    description: "The locations to which the Bandwidth Control Rule applies"
    type: list
    elements: int
    required: false
  location_groups:
    description: "The location groups to which the Bandwidth Control Rule applies"
    type: list
    elements: int
    required: false
  time_windows:
    description: "The time interval in which the Bandwidth Control Rule applies"
    type: list
    elements: int
    required: false
  protocols:
    description:
        - Protocol criteria
    required: false
    type: list
    elements: str
    choices:
        - WEBSOCKETSSL_RULE
        - WEBSOCKET_RULE
        - DOHTTPS_RULE
        - TUNNELSSL_RULE
        - HTTP_PROXY
        - FOHTTP_RULE
        - FTP_RULE
        - HTTPS_RULE
        - HTTP_RULE
        - SSL_RULE
        - TUNNEL_RULE
"""

EXAMPLES = r"""
- name: Create/update Bandwidth Control Rule
  zscaler.ziacloud.zia_bandwidth_control_rules:
    provider: '{{ provider }}'
    state: present
    name: "Ansible_Example_Rule"
    description: "TT#1965232865"
    enabled: true
    order: 1
    max_bandwidth: 100
    min_bandwidth: 20
    bandwidth_class_ids:
      - 4
      - 8
    locations:
      - 123545
      - 654654
    protocols:
      - WEBSOCKETSSL_RULE
      - WEBSOCKET_RULE
      - DOHTTPS_RULE
      - TUNNELSSL_RULE
      - HTTP_PROXY
      - FOHTTP_RULE
      - FTP_RULE
      - HTTPS_RULE
      - HTTP_RULE
      - SSL_RULE
      - TUNNEL_RULE
"""

RETURN = r"""
# Returns information on the newly created Bandwidth Control Rule.
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
    """
    Normalize rule data by removing computed values.
    """
    if not rule:
        return {}

    normalized = rule.copy()
    computed_values = ["enable_full_logging", "action"]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)

    params = [
        "id",
        "name",
        "description",
        "order",
        "rank",
        "enabled",
        "max_bandwidth",
        "max_bandwidth",
        "protocols",
        "bandwidth_classes",
        "locations",
        "location_groups",
        "labels",
        "time_windows",
    ]

    rule = {
        param: module.params.get(param)
        for param in params
        if module.params.get(param) is not None
    }

    # Validate and format country codes
    dest_countries = rule.get("dest_countries")
    if dest_countries:
        validated_dest_countries = []
        for country_code in dest_countries:
            if validate_iso3166_alpha2(country_code):
                validated_dest_countries.append(f"COUNTRY_{country_code}")
            else:
                module.fail_json(
                    msg=f"Invalid destination country code '{country_code}'. Must be ISO3166 Alpha2."
                )
        rule["dest_countries"] = validated_dest_countries

    rule_id = rule.get("id")
    rule_name = rule.get("name")

    existing_rule = None
    if rule_id is not None:
        result, _unused, error = client.bandwidth_control_rules.get_rule(
            rule_id=rule_id
        )
        if error:
            module.fail_json(
                msg=f"Error fetching rule with id {rule_id}: {to_native(error)}"
            )
        if result:
            existing_rule = result.as_dict()
    else:
        result, _unused, error = client.bandwidth_control_rules.list_rules()
        if error:
            module.fail_json(msg=f"Error listing rules: {to_native(error)}")
        if result:
            for rule_ in result:
                if rule_.name == rule_name:
                    existing_rule = rule_.as_dict()
                    break

    # Handle predefined/default rules
    if (
        state == "absent"
        and existing_rule
        and (existing_rule.get("default_rule", False))
    ):
        module.exit_json(changed=False, msg="Deletion of default rule is not allowed.")

    # Normalize and compare rules
    desired_rule = normalize_rule(rule)
    current_rule = normalize_rule(existing_rule) if existing_rule else {}

    def preprocess_rule(rule_dict, params):
        """Preprocess rule attributes for comparison."""
        processed = rule_dict.copy()
        for attr in params:
            if attr in processed and processed[attr] is not None:
                if isinstance(processed[attr], list):
                    if all(
                        isinstance(item, dict) and "id" in item
                        for item in processed[attr]
                    ):
                        processed[attr] = [item["id"] for item in processed[attr]]
                    else:
                        processed[attr] = sorted(processed[attr])
        return processed

    desired_processed = preprocess_rule(desired_rule, params)
    current_processed = preprocess_rule(current_rule, params)

    # List of attributes where empty list and None should be treated as equivalent
    list_attributes = [
        "bandwidth_classes",
        "protocols",
        "labels",
        "locations",
        "location_groups",
        "departments",
        "time_windows",
    ]

    differences_detected = False
    for key in params:
        desired_value = desired_processed.get(key)
        current_value = current_processed.get(key)

        # Skip ID comparison if not in desired rule
        if key == "id" and desired_value is None and current_value is not None:
            continue

        # Convert state to enabled boolean
        if key == "enabled" and "state" in current_rule:
            current_value = current_rule["state"] == "ENABLED"

        # Handle list attributes - treat None and [] as equivalent
        if key in list_attributes:
            if desired_value in (None, []) and current_value in (None, []):
                continue
            if desired_value is None:
                desired_value = []
            if current_value is None:
                current_value = []

        # Sort lists of IDs for comparison
        if isinstance(desired_value, list) and isinstance(current_value, list):
            if all(isinstance(x, int) for x in desired_value) and all(
                isinstance(x, int) for x in current_value
            ):
                desired_value = sorted(desired_value)
                current_value = sorted(current_value)

        if current_value != desired_value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
            )

    if module.check_mode:
        module.exit_json(
            changed=bool(
                (state == "present" and (not existing_rule or differences_detected))
                or (state == "absent" and existing_rule)
            )
        )

    if state == "present":
        if existing_rule:
            if differences_detected:
                update_data = deleteNone(
                    {
                        "rule_id": existing_rule.get("id"),
                        "name": desired_rule.get("name"),
                        "order": desired_rule.get("order"),
                        "rank": desired_rule.get("rank"),
                        "action": desired_rule.get("action"),
                        "enabled": desired_rule.get("enabled"),
                        "description": desired_rule.get("description"),
                        "protocols": desired_rule.get("protocols"),
                        "bandwidth_classes": desired_rule.get("bandwidth_classes"),
                        "labels": desired_rule.get("labels"),
                        "locations": desired_rule.get("locations"),
                        "location_groups": desired_rule.get("location_groups"),
                        "time_windows": desired_rule.get("time_windows"),
                    }
                )
                module.warn("Payload Update for SDK: {}".format(update_data))
                updated_rule, _unused, error = (
                    client.bandwidth_control_rules.update_rule(**update_data)
                )
                if error:
                    module.fail_json(msg=f"Error updating rule: {to_native(error)}")
                module.exit_json(changed=True, data=updated_rule.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule)
        else:
            create_data = deleteNone(
                {
                    "name": desired_rule.get("name"),
                    "order": desired_rule.get("order"),
                    "rank": desired_rule.get("rank"),
                    "action": desired_rule.get("action"),
                    "enabled": desired_rule.get("enabled"),
                    "description": desired_rule.get("description"),
                    "protocols": desired_rule.get("protocols"),
                    "bandwidth_classes": desired_rule.get("bandwidth_classes"),
                    "labels": desired_rule.get("labels"),
                    "locations": desired_rule.get("locations"),
                    "location_groups": desired_rule.get("location_groups"),
                    "time_windows": desired_rule.get("time_windows"),
                }
            )
            module.warn("Payload Update for SDK: {}".format(create_data))
            new_rule, _unused, error = client.bandwidth_control_rules.add_rule(
                **create_data
            )
            if error:
                module.fail_json(msg=f"Error creating rule: {to_native(error)}")
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            _unused, _unused, error = client.bandwidth_control_rules.delete_rule(
                rule_id=existing_rule.get("id")
            )
            if error:
                module.fail_json(msg=f"Error deleting rule: {to_native(error)}")
            module.exit_json(changed=True, data=existing_rule)
        else:
            module.exit_json(changed=False, data={})

    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    id_spec = dict(
        type="list",
        elements="int",
        required=False,
    )

    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        enabled=dict(type="bool", required=False),
        order=dict(type="int", required=False),
        rank=dict(type="int", required=False, default=7),
        max_bandwidth=dict(type="int", required=False),
        min_bandwidth=dict(type="int", required=False),
        protocols=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "WEBSOCKETSSL_RULE",
                "WEBSOCKET_RULE",
                "DOHTTPS_RULE",
                "TUNNELSSL_RULE",
                "HTTP_PROXY",
                "FOHTTP_RULE",
                "FTP_RULE",
                "HTTPS_RULE",
                "HTTP_RULE",
                "SSL_RULE",
                "TUNNEL_RULE",
            ],
        ),
        bandwidth_classes=id_spec,
        labels=id_spec,
        locations=id_spec,
        location_groups=id_spec,
        time_windows=id_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
