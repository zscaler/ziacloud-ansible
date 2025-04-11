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
module: zia_cloud_firewall_filtering_rule
short_description: "Firewall Filtering policy rule."
description: "Adds a new Firewall Filtering policy rule."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
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
    description: "Unique identifier for the Firewall Filtering policy rule"
    required: false
    type: int
  name:
    description: "Name of the Firewall Filtering policy rule"
    required: true
    type: str
  order:
    description: "Rule order number of the Firewall Filtering policy rule"
    required: false
    type: int
  rank:
    description: "Admin rank of the Firewall Filtering policy rule"
    required: false
    default: 7
    type: int
  enable_full_logging:
    description:
      - Aggregate The service groups together individual sessions based on  user, rule, network service, network application and records them periodically.
      - Full The service logs all sessions of the rule individually, except HTTPS or HTTPS.
      - Full logging on all other rules requires the Full Logging license. Only Block rules support full logging.
    required: false
    default: false
    type: bool
  locations:
    description: "The locations to which the Firewall Filtering policy rule applies"
    type: list
    elements: int
    required: false
  location_groups:
    description: "The location groups to which the Firewall Filtering policy rule applies"
    type: list
    elements: int
    required: false
  departments:
    description: "The departments to which the Firewall Filtering policy rule applies"
    type: list
    elements: int
    required: false
  groups:
    description: "The groups to which the Firewall Filtering policy rule applies"
    type: list
    elements: int
    required: false
  users:
    description: "The users to which the Firewall Filtering policy rule applies"
    type: list
    elements: int
    required: false
  time_windows:
    description: "The time interval in which the Firewall Filtering policy rule applies"
    type: list
    elements: int
    required: false
  workload_groups:
    description: "The list of preconfigured workload groups to which the policy must be applied."
    type: list
    elements: int
    required: false
  action:
    description: "The action the Firewall Filtering policy rule takes when packets match the rule"
    required: false
    type: str
    choices:
        - ALLOW
        - BLOCK_DROP
        - BLOCK_RESET
        - BLOCK_ICMP
        - EVAL_NWAPP
  enabled:
    description:
        - Determines whether the Firewall Filtering policy rule is enabled or disabled
    required: false
    type: bool
  description:
    description: "Additional information about the rule"
    required: false
    type: str
  src_ips:
    description:
      - User-defined source IP addresses for which the rule is applicable.
      - If not set, the rule is not restricted to a specific source IP address.
    type: list
    elements: str
    required: false
  src_ip_groups:
    description:
        - User-defined source IP address groups for which the rule is applicable.
        - If not set, the rule is not restricted to a specific source IP address group.
    type: list
    elements: int
    required: false
  dest_addresses:
    description:
      - List of destination IP addresses to which this rule will be applied.
      - CIDR notation can be used for destination IP addresses.
    type: list
    elements: str
    required: false
  dest_ip_categories:
    description:
      - IP address categories of destination for which the DNAT rule is applicable.
      - If not set, the rule is not restricted to specific destination IP categories.
    type: list
    elements: str
    required: false
  dest_countries:
    description:
      - Destination countries for which the rule is applicable.
      - If not set, the rule is not restricted to specific destination countries.
      - Provide a ISO3166 Alpha2 code.  visit the following site for reference U(https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)
    type: list
    elements: str
    required: false
  dest_ip_groups:
    description:
        - User-defined destination IP address groups on which the rule is applied.
        - If not set, the rule is not restricted to a specific destination IP address group.
    type: list
    elements: int
    required: false
  source_countries:
    description:
      - The list of source countries that must be included or excluded from the rule based on the excludeSrcCountries field value.
      - If no value is set, this field is ignored during policy evaluation and the rule is applied to all source countries.
      - Provide a ISO3166 Alpha2 code.  visit the following site for reference U(https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)
    type: list
    elements: str
    required: false
  exclude_src_countries:
    description:
      - Indicates whether the countries specified in the sourceCountries field are included or excluded from the rule.
      - A true value denotes that the specified source countries are excluded from the rule.
      - A false value denotes that the rule is applied to the source countries if there is a match.
      - Provide a ISO3166 Alpha2 code.  visit the following site for reference U(https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)
    type: bool
    required: false
  nw_services:
    description:
        - User-defined network services on which the rule is applied.
        - If not set, the rule is not restricted to a specific network service.
    type: list
    elements: int
    required: false
  nw_service_groups:
    description:
        - User-defined network service group on which the rule is applied.
        - If not set, the rule is not restricted to a specific network service group.
    type: list
    elements: int
    required: false
  nw_applications:
    description:
      - User-defined network service applications on which the rule is applied.
      - If not set, the rule is not restricted to a specific network service application.
    type: list
    elements: int
    required: false
  nw_application_groups:
    description:
        - User-defined network service application group on which the rule is applied.
        - If not set, the rule is not restricted to a specific network service application group.
    type: list
    elements: int
    required: false
  app_services:
    description: "Application services on which this rule is applied"
    type: list
    elements: int
    required: false
  app_service_groups:
    description: "Application service groups on which this rule is applied"
    type: list
    elements: int
    required: false
  labels:
    description: "Labels that are applicable to the rule."
    type: list
    elements: int
    required: false
  dest_ipv6_groups:
    description:
      - Destination IPv6 address groups for which the rule is applicable.
      - If not set, the rule is not restricted to a specific source IPv6 address group.
    type: list
    elements: int
    required: false
  src_ipv6_groups:
    description:
      - Source IPv6 address groups for which the rule is applicable.
      - If not set, the rule is not restricted to a specific source IPv6 address group.
    type: list
    elements: int
    required: false
  device_groups:
    description:
      - Name-ID pairs of device groups for which the rule must be applied.
      - This field is applicable for devices that are managed using Zscaler Client Connector.
      - If no value is set, this field is ignored during the policy evaluation.
    type: list
    elements: int
    required: false
  devices:
    description:
      - Name-ID pairs of devices for which rule must be applied.
      - Specifies devices that are managed using Zscaler Client Connector.
      - If no value is set, this field is ignored during the policy evaluation.
    type: list
    elements: int
    required: false
  device_trust_levels:
    description:
        - List of device trust levels for which the rule must be applied.
        - This field is applicable for devices that are managed using Zscaler Client Connector.
        - The trust levels are assigned to the devices based on your posture configurations.
        - If no value is set, this field is ignored during the policy evaluation.
    type: list
    elements: str
    required: false
    choices:
        - ANY
        - UNKNOWN_DEVICETRUSTLEVEL
        - LOW_TRUST
        - MEDIUM_TRUST
        - HIGH_TRUST
"""

EXAMPLES = r"""
- name: Create/update  firewall filtering rule
  zscaler.ziacloud.zia_cloud_firewall_filtering_rule:
    provider: '{{ provider }}'
    state: present
    name: "Ansible_Example_Rule"
    description: "TT#1965232865"
    action: "ALLOW"
    enabled: true
    order: 1
    enable_full_logging: true
    exclude_src_countries: true
    source_countries:
      - BR
      - CA
      - US
    dest_countries:
      - BR
      - CA
      - US
    device_trust_levels:
      - "UNKNOWN_DEVICETRUSTLEVEL"
      - "LOW_TRUST"
      - "MEDIUM_TRUST"
      - "HIGH_TRUST"
"""

RETURN = r"""
# Returns information on the newly created cloud firewall filtering rule.
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
    computed_values = []
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)

    params = [
        "id", "name", "order", "rank", "locations", "location_groups",
        "departments", "groups", "users", "time_windows", "action", "enabled",
        "description", "device_groups", "devices", "enable_full_logging",
        "src_ips", "src_ip_groups", "src_ipv6_groups", "dest_addresses",
        "dest_ip_categories", "dest_countries", "source_countries",
        "exclude_src_countries", "dest_ip_groups", "dest_ipv6_groups",
        "nw_services", "nw_service_groups", "nw_applications",
        "nw_application_groups", "app_services", "app_service_groups",
        "labels", "device_trust_levels", "workload_groups"
    ]

    rule = {param: module.params.get(param) for param in params}

    # Validate and format country codes
    source_countries = rule.get("source_countries")
    if source_countries:
        validated_source_countries = []
        for country_code in source_countries:
            if validate_iso3166_alpha2(country_code):
                validated_source_countries.append(f"COUNTRY_{country_code}")
            else:
                module.fail_json(
                    msg=f"Invalid source country code '{country_code}'. Must be ISO3166 Alpha2."
                )
        rule["source_countries"] = validated_source_countries

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

    # Validate exclude_src_countries
    if rule.get("exclude_src_countries") and not rule.get("source_countries"):
        module.fail_json(
            msg="When 'exclude_src_countries' is True, 'source_countries' must be specified."
        )

    rule_id = rule.get("id")
    rule_name = rule.get("name")

    existing_rule = None
    if rule_id is not None:
        result, _, error = client.cloud_firewall_rules.get_rule(rule_id=rule_id)
        if error:
            module.fail_json(msg=f"Error fetching rule with id {rule_id}: {to_native(error)}")
        if result:
            existing_rule = result.as_dict()
    else:
        result, _, error = client.cloud_firewall_rules.list_rules()
        if error:
            module.fail_json(msg=f"Error listing rules: {to_native(error)}")
        if result:
            for rule_ in result:
                if rule_.name == rule_name:
                    existing_rule = rule_.as_dict()
                    break

    # Handle predefined/default rules
    if state == "absent" and existing_rule and (
        existing_rule.get("default_rule", False) or existing_rule.get("predefined", False)
    ):
        module.exit_json(
            changed=False,
            msg="Deletion of default or predefined rule is not allowed."
        )

    # Normalize and compare rules
    desired_rule = normalize_rule(rule)
    current_rule = normalize_rule(existing_rule) if existing_rule else {}

    def preprocess_rule(rule_dict, params):
        """Preprocess rule attributes for comparison."""
        processed = rule_dict.copy()
        for attr in params:
            if attr in processed and processed[attr] is not None:
                if isinstance(processed[attr], list):
                    if all(isinstance(item, dict) and "id" in item for item in processed[attr]):
                        processed[attr] = [item["id"] for item in processed[attr]]
                    else:
                        processed[attr] = sorted(processed[attr])
        return processed

    desired_processed = preprocess_rule(desired_rule, params)
    current_processed = preprocess_rule(current_rule, params)

    # List of attributes where empty list and None should be treated as equivalent
    list_attributes = [
        "locations", "location_groups", "departments", "groups", "users",
        "time_windows", "device_groups", "devices", "src_ips", "src_ip_groups",
        "src_ipv6_groups", "dest_addresses", "dest_ip_categories", "dest_countries",
        "source_countries", "dest_ip_groups", "dest_ipv6_groups", "nw_services",
        "nw_service_groups", "nw_applications", "nw_application_groups",
        "app_services", "app_service_groups", "labels", "device_trust_levels",
        "workload_groups"
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

        # Skip exclude_src_countries if not specified
        if key == "exclude_src_countries" and module.params.get("exclude_src_countries") is None:
            continue

        # Sort lists of IDs for comparison
        if isinstance(desired_value, list) and isinstance(current_value, list):
            if all(isinstance(x, int) for x in desired_value) and all(isinstance(x, int) for x in current_value):
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
                (state == "present" and (not existing_rule or differences_detected)) or
                (state == "absent" and existing_rule)
            )
        )

    if state == "present":
        if existing_rule:
            if differences_detected:
                update_data = deleteNone({
                    "rule_id": existing_rule.get("id"),
                    "name": desired_rule.get("name"),
                    "order": desired_rule.get("order"),
                    "rank": desired_rule.get("rank"),
                    "action": desired_rule.get("action"),
                    "enabled": desired_rule.get("enabled"),
                    "description": desired_rule.get("description"),
                    "enable_full_logging": desired_rule.get("enable_full_logging"),
                    "src_ips": desired_rule.get("src_ips"),
                    "dest_addresses": desired_rule.get("dest_addresses"),
                    "dest_ip_categories": desired_rule.get("dest_ip_categories"),
                    "dest_countries": desired_rule.get("dest_countries"),
                    "source_countries": desired_rule.get("source_countries"),
                    "exclude_src_countries": desired_rule.get("exclude_src_countries"),
                    "device_trust_levels": desired_rule.get("device_trust_levels"),
                    "device_groups": desired_rule.get("device_groups"),
                    "devices": desired_rule.get("devices"),
                    "nw_applications": desired_rule.get("nw_applications"),
                    "dest_ip_groups": desired_rule.get("dest_ip_groups"),
                    "nw_services": desired_rule.get("nw_services"),
                    "nw_service_groups": desired_rule.get("nw_service_groups"),
                    "nw_application_groups": desired_rule.get("nw_application_groups"),
                    "app_services": desired_rule.get("app_services"),
                    "app_service_groups": desired_rule.get("app_service_groups"),
                    "labels": desired_rule.get("labels"),
                    "locations": desired_rule.get("locations"),
                    "location_groups": desired_rule.get("location_groups"),
                    "departments": desired_rule.get("departments"),
                    "groups": desired_rule.get("groups"),
                    "users": desired_rule.get("users"),
                    "time_windows": desired_rule.get("time_windows"),
                    "src_ip_groups": desired_rule.get("src_ip_groups"),
                    "workload_groups": desired_rule.get("workload_groups"),
                })

                updated_rule, _, error = client.cloud_firewall_rules.update_rule(**update_data)
                if error:
                    module.fail_json(msg=f"Error updating rule: {to_native(error)}")
                module.exit_json(changed=True, data=updated_rule.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule)
        else:
            create_data = deleteNone({
                "name": desired_rule.get("name"),
                "order": desired_rule.get("order"),
                "rank": desired_rule.get("rank"),
                "action": desired_rule.get("action"),
                "enabled": desired_rule.get("enabled"),
                "description": desired_rule.get("description"),
                "enable_full_logging": desired_rule.get("enable_full_logging"),
                "src_ips": desired_rule.get("src_ips"),
                "dest_addresses": desired_rule.get("dest_addresses"),
                "dest_ip_categories": desired_rule.get("dest_ip_categories"),
                "dest_countries": desired_rule.get("dest_countries"),
                "source_countries": desired_rule.get("source_countries"),
                "exclude_src_countries": desired_rule.get("exclude_src_countries"),
                "device_trust_levels": desired_rule.get("device_trust_levels"),
                "device_groups": desired_rule.get("device_groups"),
                "devices": desired_rule.get("devices"),
                "nw_applications": desired_rule.get("nw_applications"),
                "dest_ip_groups": desired_rule.get("dest_ip_groups"),
                "dest_ipv6_groups": desired_rule.get("dest_ipv6_groups"),
                "nw_services": desired_rule.get("nw_services"),
                "nw_service_groups": desired_rule.get("nw_service_groups"),
                "nw_application_groups": desired_rule.get("nw_application_groups"),
                "app_services": desired_rule.get("app_services"),
                "app_service_groups": desired_rule.get("app_service_groups"),
                "labels": desired_rule.get("labels"),
                "locations": desired_rule.get("locations"),
                "location_groups": desired_rule.get("location_groups"),
                "departments": desired_rule.get("departments"),
                "groups": desired_rule.get("groups"),
                "users": desired_rule.get("users"),
                "time_windows": desired_rule.get("time_windows"),
                "src_ip_groups": desired_rule.get("src_ip_groups"),
                "src_ipv6_groups": desired_rule.get("src_ipv6_groups"),
                "workload_groups": desired_rule.get("workload_groups"),
            })

            new_rule, _, error = client.cloud_firewall_rules.add_rule(**create_data)
            if error:
                module.fail_json(msg=f"Error creating rule: {to_native(error)}")
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            _, _, error = client.cloud_firewall_rules.delete_rule(rule_id=existing_rule.get("id"))
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
        device_groups=id_spec,
        devices=id_spec,
        nw_applications=id_spec,
        dest_ip_groups=id_spec,
        dest_ipv6_groups=id_spec,
        nw_services=id_spec,
        nw_service_groups=id_spec,
        nw_application_groups=id_spec,
        app_services=id_spec,
        app_service_groups=id_spec,
        labels=id_spec,
        locations=id_spec,
        location_groups=id_spec,
        departments=id_spec,
        groups=id_spec,
        users=id_spec,
        time_windows=id_spec,
        src_ip_groups=id_spec,
        src_ipv6_groups=id_spec,
        workload_groups=id_spec,
        src_ips=dict(type="list", elements="str", required=False),
        dest_addresses=dict(type="list", elements="str", required=False),
        dest_ip_categories=dict(type="list", elements="str", required=False),
        dest_countries=dict(type="list", elements="str", required=False),
        source_countries=dict(type="list", elements="str", required=False),
        exclude_src_countries=dict(type="bool", required=False),
        enable_full_logging=dict(type="bool", default=False, required=False),
        action=dict(
            type="str",
            required=False,
            choices=["ALLOW", "BLOCK_DROP", "BLOCK_RESET", "BLOCK_ICMP", "EVAL_NWAPP"],
        ),
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
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()