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
module: zia_forwarding_control_policy
short_description: "Forwarding Control policy rule."
description: "Adds a new Forwarding Control policy rule."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
    - zscaler.zpacloud.fragments.credentials_set
    - zscaler.zpacloud.fragments.provider
    - zscaler.zpacloud.fragments.enabled_state
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
    elements: str
    required: false
  location_groups:
    description: "The location groups to which the Forwarding Control policy rule applies"
    type: list
    elements: str
    required: false
  ec_groups:
    description: "Name-ID pairs of the Zscaler Cloud Connector groups to which the forwarding rule applies"
    type: list
    elements: str
    required: false
  departments:
    description: "The departments to which the Forwarding Control policy rule applies"
    type: list
    elements: str
    required: false
  groups:
    description: "The groups to which the Forwarding Control policy rule applies"
    type: list
    elements: str
    required: false
  users:
    description: "The users to which the Forwarding Control policy rule applies"
    type: list
    elements: str
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
    type: str
    choices:
        - true
        - false
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
    elements: str
    required: false
  src_ipv6_groups:
    description:
        - Source IPv6 address groups for which the rule is applicable.
        - If not set, the rule is not restricted to a specific source IPv6 address group.
    type: list
    elements: str
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
    elements: str
    required: false
  dest_ipv6_groups:
    description:
        - Destination IPv6 address groups for which the rule is applicable.
        - If not set, the rule is not restricted to a specific source IPv6 address group.
    type: list
    elements: str
    required: false
  nw_services:
    description:
        - User-defined network services on which the rule is applied.
        - If not set, the rule is not restricted to a specific network service.
    type: list
    elements: str
    required: false
  nw_service_groups:
    description:
        - User-defined network service group on which the rule is applied.
        - If not set, the rule is not restricted to a specific network service group.
    type: list
    elements: str
    required: false
  nw_applications:
    description:
      - User-defined network service applications on which the rule is applied.
      - If not set, the rule is not restricted to a specific network service application.
    type: list
    elements: str
    required: false
  nw_application_groups:
    description:
        - User-defined network service application group on which the rule is applied.
        - If not set, the rule is not restricted to a specific network service application group.
    type: list
    elements: str
    required: false
  app_service_groups:
    description: "Application service groups on which this rule is applied"
    type: list
    elements: str
    required: false
  labels:
    description: "Labels that are applicable to the rule."
    type: list
    elements: str
    required: false
  devices:
    description:
      - Name-ID pairs of devices for which the rule must be applied.
      - Specifies devices that are managed using Zscaler Client Connector.
      - If no value is set, this field is ignored during the policy evaluation.
    type: list
    elements: str
    required: false
  device_groups:
    description:
      - Name-ID pairs of devices for which the rule must be applied.
      - Specifies devices that are managed using Zscaler Client Connector.
      - If no value is set, this field is ignored during the policy evaluation.
    type: list
    elements: str
    required: false
  proxy_gateway:
    description:
        - The proxy gateway for which the rule is applicable.
        - This field is applicable only for the Proxy Chaining forwarding method.
    type: list
    elements: str
    required: false
  zpa_gateway:
    description:
        - The ZPA Server Group for which this rule is applicable.
        - Only the Server Groups that are associated with the selected Application Segments are allowed.
        - This field is applicable only for the ZPA forwarding method.
    type: list
    elements: str
    required: false
  zpa_app_segments:
    description:
        - The list of ZPA Application Segments for which this rule is applicable.
        - This field is applicable only for the ZPA Gateway forwarding method.
    type: list
    elements: str
    required: false
  zpa_application_segments:
    description:
        - List of ZPA Application Segments for which this rule is applicable.
        - This field is applicable only for the ECZPA forwarding method (used for Zscaler Cloud Connector).
    type: list
    elements: str
    required: false
  zpa_application_segment_groups:
    description:
        - List of ZPA Application Segment Groups for which this rule is applicable.
        - This field is applicable only for the ECZPA forwarding method (used for Zscaler Cloud Connector).
    type: list
    elements: str
    required: false
"""

EXAMPLES = """
- name: Create/update Forwarding Control ZPA Forward Method
    zscaler.ziacloud.zia_forwarding_control_policy:
      provider: '{{ zia_cloud }}'
      state: absent
      name: Example
      description: TT#1965232865
      type: FORWARDING
      forward_method: DIRECT
      enabled: true
      order: 1
      zpa_gateway
        - id: 2590247
          name: ZPA_GW01
"""

RETURN = """
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
        normalized.pop(attr, None)

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
                module.fail_json(msg=f"The {missing_attrs_str} are required for ZPA forwarding")

        elif forward_method == "DIRECT":
            prohibited_attrs = ["zpa_gateway", "proxy_gateway", "zpa_app_segments", "zpa_application_segments", "zpa_application_segment_groups"]
            for attr in prohibited_attrs:
                if is_set(attr):
                    module.fail_json(msg=f"{attr} attribute cannot be set when type is 'FORWARDING' and forward_method is 'DIRECT'")

        elif forward_method == "PROXYCHAIN":
            if not is_set("proxy_gateway"):
                module.fail_json(msg="Proxy gateway is mandatory for Proxy Chaining forwarding")
            prohibited_attrs = ["zpa_gateway", "zpa_app_segments", "zpa_application_segments", "zpa_application_segment_groups"]
            for attr in prohibited_attrs:
                if is_set(attr):
                    module.fail_json(msg=f"{attr} attribute cannot be set when type is 'FORWARDING' and forward_method is 'PROXYCHAIN'")

    return None  # Return None to indicate no error

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
        "device_groups",
        "src_ips",
        "src_ip_groups",
        "src_ipv6_groups",
        "dest_addresses",
        "dest_ip_categories",
        "dest_countries",
        "res_categories",
        "source_countries",
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
    for param_name in params:
        rule[param_name] = module.params.get(param_name, None)

    # Validate forwarding rule constraints
    validation_error = validate_forwarding_rule_constraints(module)
    if validation_error:
        return validation_error  # This will terminate the execution if there's a validation error

    # Perform validation and prepending 'COUNTRY_' for source_countries
    source_countries = rule.get("source_countries")
    if source_countries:
        validated_source_countries = []
        for country_code in source_countries:
            if validate_iso3166_alpha2(country_code):
                validated_source_countries.append(f"COUNTRY_{country_code}")
            else:
                module.fail_json(
                    msg=f"The source country code '{country_code}' is not a valid ISO3166 Alpha2 code. Please visit the following site for reference: https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes"
                )
        rule["source_countries"] = validated_source_countries

    # Perform validation and prepending 'COUNTRY_' for dest_countries
    dest_countries = rule.get("dest_countries")
    if dest_countries:
        validated_dest_countries = []
        for country_code in dest_countries:
            if validate_iso3166_alpha2(country_code):
                validated_dest_countries.append(f"COUNTRY_{country_code}")
            else:
                module.fail_json(
                    msg=f"The destination country code '{country_code}' is not a valid ISO3166 Alpha2 code. Please visit the following site for reference: https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes"
                )
        rule["dest_countries"] = validated_dest_countries

    rule_id = rule.get("id", None)
    rule_name = rule.get("name", None)

    existing_rule = None
    if rule_id is not None:
        ruleBox = client.forwarding_control.get_rule(rule_id=rule_id)
        if ruleBox is not None:
            existing_rule = ruleBox.to_dict()
    elif rule_name is not None:
        rules = client.forwarding_control.list_rules().to_list()
        for rule_ in rules:
            if rule_.get("name") == rule_name:
                existing_rule = rule_

    # Normalize and compare existing and desired data
    desired_rule = normalize_rule(rule)
    current_rule = normalize_rule(existing_rule) if existing_rule else {}

    def preprocess_rules(rule, params):
        """
        Preprocess specific attributes in the rule based on their type and structure.
        :param rule: Dict containing the rule data.
        :param params: List of attribute names to be processed.
        :return: Preprocessed rule.
        """
        for attr in params:
            if attr in rule and rule[attr] is not None:
                # Process list attributes
                if isinstance(rule[attr], list):
                    # If list contains dictionaries with 'id', extract IDs
                    if all(
                        isinstance(item, dict) and "id" in item for item in rule[attr]
                    ):
                        rule[attr] = [item["id"] for item in rule[attr]]
                    else:
                        # Sort lists for consistent order
                        rule[attr] = sorted(rule[attr])
                # Add more conditions here if needed for other types
        return rule

    existing_rule_preprocessed = preprocess_rules(current_rule, params)
    desired_rule_preprocessed = preprocess_rules(desired_rule, params)

    # Then proceed with your comparison logic
    differences_detected = False
    for key in params:
        desired_value = desired_rule_preprocessed.get(key)
        current_value = existing_rule_preprocessed.get(key)

        # Handling for list attributes where None should be treated as an empty list
        if isinstance(current_value, list) and desired_value is None:
            desired_value = []

        # Skip comparison for 'id' if it's not in the desired rule but present in the existing rule
        if key == "id" and desired_value is None and current_value is not None:
            continue

        # Convert 'state' in current_rule to boolean 'enabled'
        if key == "enabled" and "state" in current_rule:
            current_value = current_rule["state"] == "ENABLED"

        # Handling None values for all attributes
        if desired_value is None and key != "enabled":
            # Explicitly setting to empty list or empty value based on type
            rule[key] = [] if isinstance(current_value, list) else None

        # Special handling for lists of IDs like device_groups
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

    if existing_rule is not None:
        id = existing_rule.get("id")
        existing_rule.update(rule)
        existing_rule["id"] = id

    module.warn(f"Final payload being sent to SDK: {rule}")
    if state == "present":
        if existing_rule is not None:
            if differences_detected:
                """Update"""
                update_rule = deleteNone(
                    dict(
                        rule_id=existing_rule.get("id"),
                        name=existing_rule.get("name"),
                        order=existing_rule.get("order"),
                        rank=existing_rule.get("rank"),
                        type=existing_rule.get("type"),
                        forward_method=existing_rule.get("forward_method"),
                        enabled=existing_rule.get("enabled"),
                        description=existing_rule.get("description"),
                        src_ips=existing_rule.get("src_ips"),
                        dest_addresses=existing_rule.get("dest_addresses"),
                        dest_ip_categories=existing_rule.get("dest_ip_categories"),
                        dest_countries=existing_rule.get("dest_countries"),
                        res_categories=existing_rule.get("res_categories"),
                        source_countries=existing_rule.get("source_countries"),
                        device_groups=existing_rule.get("device_groups"),
                        nw_applications=existing_rule.get("nw_applications"),
                        dest_ip_groups=existing_rule.get("dest_ip_groups"),
                        nw_services=existing_rule.get("nw_services"),
                        nw_service_groups=existing_rule.get("nw_service_groups"),
                        nw_application_groups=existing_rule.get(
                            "nw_application_groups"
                        ),
                        app_service_groups=existing_rule.get("app_service_groups"),
                        labels=existing_rule.get("labels"),
                        locations=existing_rule.get("locations"),
                        location_groups=existing_rule.get("location_groups"),
                        ec_groups=existing_rule.get("ec_groups"),
                        departments=existing_rule.get("departments"),
                        groups=existing_rule.get("groups"),
                        users=existing_rule.get("users"),
                        src_ip_groups=existing_rule.get("src_ip_groups"),
                        proxy_gateway=existing_rule.get("proxy_gateway"),
                        zpa_gateway=existing_rule.get("zpa_gateway"),
                        zpa_app_segments=existing_rule.get("zpa_app_segments"),
                        zpa_application_segments=existing_rule.get(
                            "zpa_application_segments"
                        ),
                        zpa_application_segment_groups=existing_rule.get(
                            "zpa_application_segment_groups"
                        ),
                    )
                )
                module.warn("Payload Update for SDK: {}".format(update_rule))
                updated_rule = client.forwarding_control.update_rule(
                    **update_rule
                ).to_dict()
                module.exit_json(changed=True, data=updated_rule)
        else:
            module.warn("Creating new rule as no existing rule found")
            """Create"""
            create_rule = deleteNone(
                dict(
                    name=rule.get("name"),
                    description=rule.get("description"),
                    order=rule.get("order"),
                    rank=rule.get("rank"),
                    type=rule.get("type"),
                    forward_method=rule.get("forward_method"),
                    enabled=rule.get("enabled"),
                    src_ips=rule.get("src_ips"),
                    dest_addresses=rule.get("dest_addresses"),
                    dest_ip_categories=rule.get("dest_ip_categories"),
                    dest_countries=rule.get("dest_countries"),
                    res_categories=rule.get("res_categories"),
                    source_countries=rule.get("source_countries"),
                    device_groups=rule.get("device_groups"),
                    nw_applications=rule.get("nw_applications"),
                    dest_ip_groups=rule.get("dest_ip_groups"),
                    dest_ipv6_groups=rule.get("dest_ipv6_groups"),
                    nw_services=rule.get("nw_services"),
                    nw_service_groups=rule.get("nw_service_groups"),
                    nw_application_groups=rule.get("nw_application_groups"),
                    app_service_groups=rule.get("app_service_groups"),
                    labels=rule.get("labels"),
                    locations=rule.get("locations"),
                    location_groups=rule.get("location_groups"),
                    ec_groups=rule.get("ec_groups"),
                    departments=rule.get("departments"),
                    groups=rule.get("groups"),
                    users=rule.get("users"),
                    src_ip_groups=rule.get("src_ip_groups"),
                    src_ipv6_groups=rule.get("src_ipv6_groups"),
                    proxy_gateway=rule.get("proxy_gateway"),
                    zpa_gateway=rule.get("zpa_gateway"),
                    zpa_app_segments=rule.get("zpa_app_segments"),
                    zpa_application_segments=rule.get("zpa_application_segments"),
                    zpa_application_segment_groups=rule.get(
                        "zpa_application_segment_groups"
                    ),
                )
            )
            module.warn("Payload for SDK: {}".format(create_rule))
            new_rule = client.forwarding_control.add_rule(**create_rule).to_dict()
            module.exit_json(changed=True, data=new_rule)
    elif (
        state == "absent"
        and existing_rule is not None
        and existing_rule.get("id") is not None
    ):
        code = client.forwarding_control.delete_rule(rule_id=existing_rule.get("id"))
        if code > 299:
            module.exit_json(changed=False, data=None)
        module.exit_json(changed=True, data=existing_rule)
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
        external_id=dict(type="int", required=True),
        name=dict(type="str", required=True),
    )
    argument_spec.update(
        id=dict(type="str", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        enabled=dict(type="bool", required=False),
        order=dict(type="int", required=True),
        rank=dict(type="int", required=False, default=7),
        src_ips=dict(type="list", elements="str", required=False),
        dest_addresses=dict(type="list", elements="str", required=False),
        dest_ip_categories=dict(type="list", elements="str", required=False),
        dest_countries=dict(type="list", elements="str", required=False),
        res_categories=dict(type="list", elements="str", required=False),
        source_countries=dict(type="list", elements="str", required=False),
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
        device_groups=id_spec,
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
        proxy_gateway=id_name_dict_spec,
        zpa_gateway=id_name_dict_spec,
        zpa_app_segments=external_id_name_dict_spec,
        zpa_application_segments=external_id_name_dict_spec,
        zpa_application_segment_groups=external_id_name_dict_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
