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
module: zia_forwarding_control_rule
short_description: "Forwarding Control policy rule"
description: "Adds a new Forwarding Control policy rule"
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
    description: "Unique identifier for the Forwarding Control policy rule"
    required: false
    type: int
  name:
    description: "Name of the Forwarding Control policy rule"
    required: true
    type: str
  description:
    description: "Indicates whether the forwarding rule is enabled or disabled"
    required: false
    type: str
  order:
    description: "Rule order number of the Forwarding Control policy rule"
    required: true
    type: int
  rank:
    description: "Admin rank of the Forwarding Control policy rule"
    required: false
    default: 7
    type: int
  locations:
    description: "The locations to which the Forwarding Control policy rule applies"
    type: list
    elements: int
    required: false
  location_groups:
    description: "The location groups to which the Forwarding Control policy rule applies"
    type: list
    elements: int
    required: false
  ec_groups:
    description: "Name-ID pairs of the Zscaler Cloud Connector groups to which the forwarding rule applies"
    type: list
    elements: int
    required: false
  departments:
    description: "The departments to which the Forwarding Control policy rule applies"
    type: list
    elements: int
    required: false
  groups:
    description: "The groups to which the Forwarding Control policy rule applies"
    type: list
    elements: int
    required: false
  users:
    description: "The users to which the Forwarding Control policy rule applies"
    type: list
    elements: int
    required: false
  type:
    description: "The rule type selected from the available options"
    required: false
    type: str
    choices:
        - FIREWALL
        - DNS
        - DNAT
        - SNAT
        - FORWARDING
        - INTRUSION_PREVENTION
        - EC_DNS
        - EC_RDR
        - EC_SELF
        - DNS_RESPONSE
  forward_method:
    description: "The type of traffic forwarding method selected from the available options"
    required: false
    type: str
    choices:
        - INVALID
        - DIRECT
        - PROXYCHAIN
        - ZIA
        - ZPA
        - ECZPA
        - ECSELF
        - DROP
  enabled:
    description: Determines whether the Forwarding Control policy rule is enabled or disabled
    required: false
    type: bool
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
  src_ipv6_groups:
    description:
        - Source IPv6 address groups for which the rule is applicable.
        - If not set, the rule is not restricted to a specific source IPv6 address group.
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
  res_categories:
    description: List of destination domain categories to which the rule applies
    type: list
    elements: str
    required: false
  dest_countries:
    description:
      - Destination countries for which the rule is applicable.
      - If not set, the rule is not restricted to specific destination countries.
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
  dest_ipv6_groups:
    description:
        - Destination IPv6 address groups for which the rule is applicable.
        - If not set, the rule is not restricted to a specific source IPv6 address group.
    type: list
    elements: int
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
  proxy_gateway:
    description:
      - The proxy gateway for which the rule is applicable.
      - This field is applicable only for the Proxy Chaining forwarding method.
    type: dict
    required: false
    suboptions:
      id:
        description: The Identifier that uniquely identifies Proxy Gateway entity
        type: int
        required: true
      name:
        description: The configured name of the Proxy Gateway entity
        type: str
        required: true
  zpa_gateway:
    description:
      - The ZPA Server Group for which this rule is applicable.
      - Only the Server Groups that are associated with the selected Application Segments are allowed.
      - This field is applicable only for the ZPA forwarding method.
    type: dict
    required: false
    suboptions:
      id:
        description: The Identifier that uniquely identifies the ZPA Gateway entity
        type: int
        required: true
      name:
        description: The configured name of the ZPA Gateway entity
        type: str
        required: true
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
  zpa_application_segments:
    description:
      - List of ZPA Application Segments for which this rule is applicable.
      - This field is applicable only for the ECZPA forwarding method (used for Zscaler Cloud Connector).
    type: list
    elements: dict
    required: false
    suboptions:
      id:
        description: A unique identifier assigned to the Application Segment
        type: int
        required: true
      name:
        description: The name of the Application Segment
        type: str
        required: true
  zpa_application_segment_groups:
    description:
      - List of ZPA Application Segment Groups for which this rule is applicable.
      - This field is applicable only for the ECZPA forwarding method (used for Zscaler Cloud Connector).
    type: list
    elements: dict
    required: false
    suboptions:
      id:
        description: A unique identifier assigned to the Application Segment Group
        type: int
        required: true
      name:
        description: The name of the Application Segment Group
        type: str
        required: true
"""

EXAMPLES = r"""
- name: Create/Update Forwarding Control DIRECT Forward Method
  zscaler.ziacloud.zia_forwarding_control_rule:
    provider: '{{ provider }}'
    name: 'Example'
    description: 'TT#1965232865'
    type: 'FORWARDING'
    forward_method: 'DIRECT'
    enabled: true
    order: 1
    zpa_gateway:
      - id: 2590247
        name: 'ZPA_GW01'

- name: Create/Update Forwarding Control ZPA Forward Method
  zscaler.ziacloud.zia_forwarding_control_rule:
    provider: '{{ provider }}'
    name: 'Example'
    description: 'TT#1965232865'
    type: 'FORWARDING'
    forward_method: 'ZPA'
    enabled: true
    order: 1
    zpa_app_segments:
      - external_id: "216199618143393478"
        name: Example300
      - external_id: "216199618143393479"
        name: Example400
    zpa_gateway:
      - id: 2590247
        name: 'ZPA_GW01'
"""

RETURN = r"""
# Returns information on the newly created cloud Forwarding Control rule.
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
    Normalize rule data by setting computed values.
    """
    normalized = rule.copy()

    computed_values = []

    for attr in computed_values:
        if attr in normalized and normalized[attr] is None:
            normalized[attr] = []

        if attr == "zpa_app_segments" and attr in normalized:
            normalized[attr] = [
                {
                    "external_id": segment.get("external_id", ""),
                    "name": segment.get("name", ""),
                }
                for segment in normalized[attr] or []
            ]
        elif attr in normalized:
            normalized[attr] = normalized[attr]
        else:
            normalized[attr] = []

    return normalized


def validate_forwarding_rule_constraints(module):
    forward_method = module.params.get("forward_method")
    rule_type = module.params.get("type")

    def is_set(attr):
        return module.params.get(attr) is not None

    if rule_type == "FORWARDING":
        if forward_method == "ZPA":
            required_attrs = ["zpa_app_segments", "zpa_gateway"]
            missing_attrs = [attr for attr in required_attrs if not is_set(attr)]
            if missing_attrs:
                missing_attrs_str = ", ".join(missing_attrs)
                module.fail_json(
                    msg=f"The {missing_attrs_str} are required for ZPA forwarding"
                )

        elif forward_method == "DIRECT":
            prohibited_attrs = [
                "zpa_gateway",
                "proxy_gateway",
                "zpa_app_segments",
                "zpa_application_segments",
                "zpa_application_segment_groups",
            ]
            for attr in prohibited_attrs:
                if is_set(attr):
                    module.fail_json(
                        msg=f"{attr} attribute cannot be set when type is 'FORWARDING' and forward_method is 'DIRECT'"
                    )

        elif forward_method == "PROXYCHAIN":
            if not is_set("proxy_gateway"):
                module.fail_json(
                    msg="Proxy gateway is mandatory for Proxy Chaining forwarding"
                )
            prohibited_attrs = [
                "zpa_gateway",
                "zpa_app_segments",
                "zpa_application_segments",
                "zpa_application_segment_groups",
            ]
            for attr in prohibited_attrs:
                if is_set(attr):
                    module.fail_json(
                        msg=f"{attr} attribute cannot be set when type is 'FORWARDING' and forward_method is 'PROXYCHAIN'"
                    )

    return None


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    rule = dict()
    params = [
        "id",
        "name",
        "description",
        "enabled",
        "order",
        "rank",
        "locations",
        "location_groups",
        "ec_groups",
        "departments",
        "groups",
        "users",
        "type",
        "forward_method",
        "src_ips",
        "src_ip_groups",
        "src_ipv6_groups",
        "dest_addresses",
        "dest_ip_categories",
        "dest_countries",
        "res_categories",
        "dest_ip_groups",
        "dest_ipv6_groups",
        "nw_services",
        "nw_service_groups",
        "nw_applications",
        "nw_application_groups",
        "app_service_groups",
        "labels",
        "proxy_gateway",
        "zpa_gateway",
        "zpa_app_segments",
        "zpa_application_segments",
        "zpa_application_segment_groups",
    ]

    rule = {param: module.params.get(param) for param in params}

    # Validate forwarding rule constraints
    validation_error = validate_forwarding_rule_constraints(module)
    if validation_error:
        return validation_error

    # Perform validation and prepending 'COUNTRY_' for dest_countries
    dest_countries = rule.get("dest_countries")
    if dest_countries:
        validated_dest_countries = []
        for country_code in dest_countries:
            if validate_iso3166_alpha2(country_code):
                validated_dest_countries.append(f"COUNTRY_{country_code}")
            else:
                module.fail_json(
                    msg=(
                        f"The destination country code '{country_code}' is not a valid ISO3166 Alpha2 code. "
                        "Please visit the following site for reference: "
                        "https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes"
                    )
                )
        rule["dest_countries"] = validated_dest_countries

    # Preprocess specific attributes
    def preprocess_attributes(rule):
        proxy = rule.get("proxy_gateway")
        if isinstance(proxy, dict) and proxy.get("id"):
            rule["proxy_gateway"] = {"id": proxy["id"], "name": proxy.get("name", "")}
        else:
            rule["proxy_gateway"] = None

        zpa = rule.get("zpa_gateway")
        if isinstance(zpa, dict) and zpa.get("id"):
            rule["zpa_gateway"] = {"id": zpa["id"], "name": zpa.get("name", "")}
        else:
            rule["zpa_gateway"] = None

        if rule.get("zpa_app_segments"):
            if rule["zpa_app_segments"] is None:
                rule["zpa_app_segments"] = []
            else:
                rule["zpa_app_segments"] = [
                    {"external_id": segment["external_id"], "name": segment["name"]}
                    for segment in rule["zpa_app_segments"]
                ]
        if rule.get("zpa_application_segments"):
            rule["zpa_application_segments"] = [
                {"id": segment["id"], "name": segment["name"]}
                for segment in rule["zpa_application_segments"]
            ]
        if rule.get("zpa_application_segment_groups"):
            rule["zpa_application_segment_groups"] = [
                {"id": segment["id"], "name": segment["name"]}
                for segment in rule["zpa_application_segment_groups"]
            ]

    preprocess_attributes(rule)

    rule_id = rule.get("id", None)
    rule_name = rule.get("name", None)

    existing_rule = None
    if rule_id is not None:
        result, _unused, error = client.forwarding_control.get_rule(rule_id=rule_id)
        if error:
            module.fail_json(
                msg=f"Error fetching rule with id {rule_id}: {to_native(error)}"
            )
        if result:
            existing_rule = result.as_dict()
    else:
        result, _unused, error = client.forwarding_control.list_rules()
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

    # Normalize and compare existing and desired data
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
        "ec_groups",
        "departments",
        "groups",
        "users",
        "src_ips",
        "src_ip_groups",
        "src_ipv6_groups",
        "dest_addresses",
        "dest_ip_categories",
        "dest_countries",
        "res_categories",
        "dest_ip_groups",
        "dest_ipv6_groups",
        "nw_services",
        "nw_service_groups",
        "nw_applications",
        "nw_application_groups",
        "app_service_groups",
        "labels",
        "proxy_gateway",
        "zpa_gateway",
        "zpa_app_segments",
        "zpa_application_segments",
        "zpa_application_segment_groups",
    ]

    differences_detected = False
    for key in params:
        desired_value = desired_processed.get(key)
        current_value = current_processed.get(key)

        # Skip ID comparison if not in desired rule
        if key == "id" and desired_value is None and current_value is not None:
            continue

        # Convert state to enabled boolean for comparison
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
        if state == "present" and (existing_rule is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_rule is not None:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_rule:
            if differences_detected:
                rule_id_to_update = existing_rule.get("id")
                if not rule_id_to_update:
                    module.fail_json(
                        msg="Cannot update rule: ID is missing from the existing resource."
                    )

                update_rule = deleteNone(
                    {
                        "rule_id": existing_rule.get("id"),
                        "name": desired_rule.get("name"),
                        "description": desired_rule.get("description"),
                        "order": desired_rule.get("order"),
                        "rank": desired_rule.get("rank"),
                        "type": desired_rule.get("type"),
                        "forward_method": desired_rule.get("forward_method"),
                        "enabled": desired_rule.get("enabled", True),
                        "src_ips": desired_rule.get("src_ips"),
                        "dest_addresses": desired_rule.get("dest_addresses"),
                        "dest_ip_categories": desired_rule.get("dest_ip_categories"),
                        "dest_countries": desired_rule.get("dest_countries"),
                        "res_categories": desired_rule.get("res_categories"),
                        "nw_applications": desired_rule.get("nw_applications"),
                        "dest_ip_groups": desired_rule.get("dest_ip_groups"),
                        "nw_services": desired_rule.get("nw_services"),
                        "nw_service_groups": desired_rule.get("nw_service_groups"),
                        "nw_application_groups": desired_rule.get(
                            "nw_application_groups"
                        ),
                        "app_service_groups": desired_rule.get("app_service_groups"),
                        "labels": desired_rule.get("labels"),
                        "locations": desired_rule.get("locations"),
                        "location_groups": desired_rule.get("location_groups"),
                        "ec_groups": desired_rule.get("ec_groups"),
                        "departments": desired_rule.get("departments"),
                        "groups": desired_rule.get("groups"),
                        "users": desired_rule.get("users"),
                        "src_ip_groups": desired_rule.get("src_ip_groups"),
                        "src_ipv6_groups": desired_rule.get("src_ipv6_groups"),
                        "proxy_gateway": desired_rule.get("proxy_gateway"),
                        "zpa_gateway": desired_rule.get("zpa_gateway"),
                        "zpa_app_segments": desired_rule.get("zpa_app_segments"),
                        "zpa_application_segments": desired_rule.get(
                            "zpa_application_segments"
                        ),
                        "zpa_application_segment_groups": desired_rule.get(
                            "zpa_application_segment_groups"
                        ),
                    }
                )

                module.warn("Payload Update for SDK: {}".format(update_rule))
                updated_rule, _unused, error = client.forwarding_control.update_rule(
                    **update_rule
                )
                if error:
                    module.fail_json(msg=f"Error updating rule: {to_native(error)}")
                module.exit_json(changed=True, data=updated_rule.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule)
        else:
            create_rule = deleteNone(
                {
                    "name": desired_rule.get("name"),
                    "description": desired_rule.get("description"),
                    "order": desired_rule.get("order"),
                    "rank": desired_rule.get("rank"),
                    "type": desired_rule.get("type"),
                    "forward_method": desired_rule.get("forward_method"),
                    "enabled": desired_rule.get("enabled", True),
                    "src_ips": desired_rule.get("src_ips"),
                    "dest_addresses": desired_rule.get("dest_addresses"),
                    "dest_ip_categories": desired_rule.get("dest_ip_categories"),
                    "dest_countries": desired_rule.get("dest_countries"),
                    "res_categories": desired_rule.get("res_categories"),
                    "nw_applications": desired_rule.get("nw_applications"),
                    "dest_ip_groups": desired_rule.get("dest_ip_groups"),
                    "nw_services": desired_rule.get("nw_services"),
                    "nw_service_groups": desired_rule.get("nw_service_groups"),
                    "nw_application_groups": desired_rule.get("nw_application_groups"),
                    "app_service_groups": desired_rule.get("app_service_groups"),
                    "labels": desired_rule.get("labels"),
                    "locations": desired_rule.get("locations"),
                    "location_groups": desired_rule.get("location_groups"),
                    "ec_groups": desired_rule.get("ec_groups"),
                    "departments": desired_rule.get("departments"),
                    "groups": desired_rule.get("groups"),
                    "users": desired_rule.get("users"),
                    "src_ip_groups": desired_rule.get("src_ip_groups"),
                    "src_ipv6_groups": desired_rule.get("src_ipv6_groups"),
                    "proxy_gateway": desired_rule.get("proxy_gateway"),
                    "zpa_gateway": desired_rule.get("zpa_gateway"),
                    "zpa_app_segments": desired_rule.get("zpa_app_segments"),
                    "zpa_application_segments": desired_rule.get(
                        "zpa_application_segments"
                    ),
                    "zpa_application_segment_groups": desired_rule.get(
                        "zpa_application_segment_groups"
                    ),
                }
            )
            module.warn("Payload for SDK: {}".format(create_rule))
            new_rule, _unused, error = client.forwarding_control.add_rule(**create_rule)
            if error:
                module.fail_json(msg=f"Error creating rule: {to_native(error)}")
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            rule_id_to_delete = existing_rule.get("id")
            if not rule_id_to_delete:
                module.fail_json(
                    msg="Cannot delete rule: ID is missing from the existing resource."
                )

            _unused, _unused, error = client.forwarding_control.delete_rule(
                rule_id=rule_id_to_delete
            )
            if error:
                module.fail_json(msg=f"Error deleting rule: {to_native(error)}")
            module.exit_json(changed=True, data=existing_rule)
        else:
            module.exit_json(changed=False, data={})

    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    id_spec = dict(
        type="list",
        elements="int",
        required=False,
    )
    # Define the spec for a dictionary with id and name
    id_name_dict_spec = dict(
        id=dict(type="int", required=True),
        name=dict(type="str", required=True),
    )
    external_id_name_dict_spec = dict(
        external_id=dict(type="str", required=True),
        name=dict(type="str", required=True),
    )

    # Define specifications for nested dictionaries
    proxy_gateway_spec = dict(
        type="dict",
        required=False,
        options=dict(
            id=dict(type="int", required=True),
            name=dict(type="str", required=True),
        ),
    )

    zpa_gateway_spec = dict(
        type="dict",
        required=False,
        options=dict(
            id=dict(type="int", required=True),
            name=dict(type="str", required=True),
        ),
    )

    # Define the spec for a list of dictionaries with external_id and name
    external_id_name_list_spec = dict(
        type="list",
        elements="dict",
        required=False,
        options=external_id_name_dict_spec,
    )

    id_name_list_spec = dict(
        type="list",
        elements="dict",
        required=False,
        options=id_name_dict_spec,
    )

    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        enabled=dict(type="bool", required=False),
        order=dict(type="int", required=False),
        rank=dict(type="int", required=False, default=7),
        src_ips=dict(type="list", elements="str", required=False),
        dest_addresses=dict(type="list", elements="str", required=False),
        dest_ip_categories=dict(type="list", elements="str", required=False),
        dest_countries=dict(type="list", elements="str", required=False),
        res_categories=dict(type="list", elements="str", required=False),
        type=dict(
            type="str",
            required=False,
            choices=[
                "FIREWALL",
                "DNS",
                "DNAT",
                "SNAT",
                "FORWARDING",
                "INTRUSION_PREVENTION",
                "EC_DNS",
                "EC_RDR",
                "EC_SELF",
                "DNS_RESPONSE",
            ],
        ),
        forward_method=dict(
            type="str",
            required=False,
            choices=[
                "INVALID",
                "DIRECT",
                "PROXYCHAIN",
                "ZIA",
                "ZPA",
                "ECZPA",
                "ECSELF",
                "DROP",
            ],
        ),
        nw_applications=id_spec,
        dest_ip_groups=id_spec,
        dest_ipv6_groups=id_spec,
        nw_services=id_spec,
        nw_service_groups=id_spec,
        nw_application_groups=id_spec,
        app_service_groups=id_spec,
        labels=id_spec,
        locations=id_spec,
        location_groups=id_spec,
        ec_groups=id_spec,
        departments=id_spec,
        groups=id_spec,
        users=id_spec,
        src_ip_groups=id_spec,
        src_ipv6_groups=id_spec,
        proxy_gateway=proxy_gateway_spec,
        zpa_gateway=zpa_gateway_spec,
        zpa_app_segments=external_id_name_list_spec,
        zpa_application_segments=id_name_list_spec,
        zpa_application_segment_groups=id_name_list_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
