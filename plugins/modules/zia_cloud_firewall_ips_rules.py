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
module: zia_cloud_firewall_ips_rules
short_description: "Firewall Filtering policy IPS rule."
description: "Adds a new Firewall Filtering policy IPS rule."
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
    description: "Unique identifier for the Firewall Filtering policy rule"
    required: false
    type: int
  name:
    description: "Name of the Firewall Filtering policy rule"
    required: true
    type: str
  description:
    description: "Additional information about the rule"
    required: false
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
  action:
    description:
      - The action configured for the rule that must take place if the traffic matches the rule criteria
      - such as allowing or blocking the traffic or bypassing the rule.
    required: false
    type: str
    choices:
        - ALLOW
        - BLOCK_DROP
        - BLOCK_RESET
        - BYPASS_IPS
  enabled:
    description:
        - Determines whether the Firewall Filtering policy ips rule is enabled or disabled
    required: false
    type: bool
  enable_full_logging:
    description:
      - Aggregate The service groups together individual sessions based on  user, rule, network service, network application and records them periodically.
      - Full The service logs all sessions of the rule individually, except HTTPS or HTTPS.
      - Full logging on all other rules requires the Full Logging license. Only Block rules support full logging.
    required: false
    default: false
    type: bool
  capture_pcap:
    description:
        - Indicates whether packet capture (PCAP) is enabled or not
    required: false
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
      - Provide a ISO3166 Alpha2 code. Visit the following site for reference U(https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)
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
  res_categories:
    description: List of destination domain categories to which the rule applies
    type: list
    elements: str
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
  threat_categories:
    description: Advanced threat categories to which the rule applies
    type: list
    elements: int
    required: false
  zpa_app_segments:
    description:
      - The list of ZPA Application Segments for which this rule is applicable.
      - This field is applicable only for the ZPA forwarding method.
    type: list
    elements: dict
    required: false
    suboptions:
      external_id:
        description: Indicates the external ID. Applicable only when this reference is of an external entity.
        type: str
        required: true
      name:
        description: The name of the Application Segment
        type: str
        required: true
  eun_template_id:
    description:
      - The EUN template ID associated with the rule
    required: false
    type: int 
  is_eun_enabled:
    description:
      - If set to true, Web EUN is enabled for the rule
    required: false
    type: bool 
"""

EXAMPLES = r"""
- name: Create/update  firewall filtering ips rule
  zscaler.ziacloud.zia_cloud_firewall_ips_rules:
    provider: '{{ provider }}'
    state: present
    name: "Ansible_Example_Rule"
    description: "TT#1965232865"
    action: "ALLOW"
    enabled: true
    order: 1
    enable_full_logging: true
    source_countries:
      - BR
      - CA
      - US
    dest_countries:
      - BR
      - CA
      - US
"""

RETURN = r"""
# Returns information on the newly created cloud firewall filtering ips rule.
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
        "id",
        "name",
        "description",
        "order",
        "rank",
        "locations",
        "location_groups",
        "departments",
        "groups",
        "users",
        "time_windows",
        "action",
        "enabled",
        "enable_full_logging",
        "capture_pcap",
        "src_ips",
        "src_ip_groups",
        "src_ipv6_groups",
        "dest_addresses",
        "dest_ip_categories",
        "dest_countries",
        "source_countries",
        "dest_ip_groups",
        "dest_ipv6_groups",
        "labels",
        "threat_categories",
        "res_categories",
        "zpa_app_segments",
        "eun_template_id",
        "is_eun_enabled",
    ]

    rule = {
        param: module.params.get(param)
        for param in params
        if module.params.get(param) is not None
    }

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

    rule_id = rule.get("id")
    rule_name = rule.get("name")

    existing_rule = None
    if rule_id is not None:
        result, _unused, error = client.cloud_firewall_ips.get_rule(rule_id=rule_id)
        if error:
            module.fail_json(
                msg=f"Error fetching rule with id {rule_id}: {to_native(error)}"
            )
        if result:
            existing_rule = result.as_dict()
    else:
        result, _unused, error = client.cloud_firewall_ips.list_rules()
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
        and (
            existing_rule.get("default_rule", False)
            or existing_rule.get("predefined", False)
        )
    ):
        module.exit_json(
            changed=False, msg="Deletion of default or predefined rule is not allowed."
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
        "locations",
        "location_groups",
        "departments",
        "groups",
        "users",
        "time_windows",
        "src_ips",
        "src_ip_groups",
        "src_ipv6_groups",
        "dest_addresses",
        "dest_ip_categories",
        "dest_countries",
        "source_countries",
        "dest_ip_groups",
        "dest_ipv6_groups",
        "labels",
        "threat_categories",
        "res_categories",
        "zpa_app_segments",
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
                        "enable_full_logging": desired_rule.get("enable_full_logging"),
                        "capture_pcap": desired_rule.get("capture_pcap"),
                        "src_ips": desired_rule.get("src_ips"),
                        "dest_addresses": desired_rule.get("dest_addresses"),
                        "dest_ip_categories": desired_rule.get("dest_ip_categories"),
                        "dest_countries": desired_rule.get("dest_countries"),
                        "res_categories": desired_rule.get("res_categories"),
                        "source_countries": desired_rule.get("source_countries"),
                        "dest_ip_groups": desired_rule.get("dest_ip_groups"),
                        "labels": desired_rule.get("labels"),
                        "locations": desired_rule.get("locations"),
                        "location_groups": desired_rule.get("location_groups"),
                        "departments": desired_rule.get("departments"),
                        "groups": desired_rule.get("groups"),
                        "users": desired_rule.get("users"),
                        "time_windows": desired_rule.get("time_windows"),
                        "src_ip_groups": desired_rule.get("src_ip_groups"),
                        "zpa_app_segments": desired_rule.get("zpa_app_segments"),
                        "threat_categories": desired_rule.get("threat_categories"),
                        "eun_template_id": desired_rule.get("eun_template_id"),
                        "is_eun_enabled": desired_rule.get("is_eun_enabled"),
                    }
                )
                module.warn("Payload Update for SDK: {}".format(update_data))
                updated_rule, _unused, error = client.cloud_firewall_ips.update_rule(
                    **update_data
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
                    "enable_full_logging": desired_rule.get("enable_full_logging"),
                    "capture_pcap": desired_rule.get("capture_pcap"),
                    "src_ips": desired_rule.get("src_ips"),
                    "dest_addresses": desired_rule.get("dest_addresses"),
                    "dest_ip_categories": desired_rule.get("dest_ip_categories"),
                    "dest_countries": desired_rule.get("dest_countries"),
                    "res_categories": desired_rule.get("res_categories"),
                    "source_countries": desired_rule.get("source_countries"),
                    "dest_ip_groups": desired_rule.get("dest_ip_groups"),
                    "labels": desired_rule.get("labels"),
                    "locations": desired_rule.get("locations"),
                    "location_groups": desired_rule.get("location_groups"),
                    "departments": desired_rule.get("departments"),
                    "groups": desired_rule.get("groups"),
                    "users": desired_rule.get("users"),
                    "time_windows": desired_rule.get("time_windows"),
                    "src_ip_groups": desired_rule.get("src_ip_groups"),
                    "zpa_app_segments": desired_rule.get("zpa_app_segments"),
                    "threat_categories": desired_rule.get("threat_categories"),
                    "eun_template_id": desired_rule.get("eun_template_id"),
                    "is_eun_enabled": desired_rule.get("is_eun_enabled"),
                }
            )
            module.warn("Payload Update for SDK: {}".format(create_data))
            new_rule, _unused, error = client.cloud_firewall_ips.add_rule(**create_data)
            if error:
                module.fail_json(msg=f"Error creating rule: {to_native(error)}")
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            _unused, _unused, error = client.cloud_firewall_ips.delete_rule(
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

    external_id_name_dict_spec = dict(
        external_id=dict(type="str", required=True),
        name=dict(type="str", required=True),
    )

    external_id_name_list_spec = dict(
        type="list",
        elements="dict",
        required=False,
        options=external_id_name_dict_spec,
    )

    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        enabled=dict(type="bool", required=False),
        order=dict(type="int", required=False),
        rank=dict(type="int", required=False, default=7),
        dest_ip_groups=id_spec,
        dest_ipv6_groups=id_spec,
        labels=id_spec,
        locations=id_spec,
        location_groups=id_spec,
        departments=id_spec,
        groups=id_spec,
        users=id_spec,
        time_windows=id_spec,
        src_ip_groups=id_spec,
        src_ipv6_groups=id_spec,
        zpa_app_segments=external_id_name_list_spec,
        threat_categories=id_spec,
        src_ips=dict(type="list", elements="str", required=False),
        dest_addresses=dict(type="list", elements="str", required=False),
        dest_ip_categories=dict(type="list", elements="str", required=False),
        dest_countries=dict(type="list", elements="str", required=False),
        source_countries=dict(type="list", elements="str", required=False),
        res_categories=dict(type="list", elements="str", required=False),
        enable_full_logging=dict(type="bool", default=False, required=False),
        capture_pcap=dict(type="bool", required=False),
        eun_template_id=dict(type="int", required=False),
        is_eun_enabled=dict(type="bool", required=False),
        action=dict(
            type="str",
            required=False,
            choices=["ALLOW", "BLOCK_DROP", "BLOCK_RESET", "BYPASS_IPS"],
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
