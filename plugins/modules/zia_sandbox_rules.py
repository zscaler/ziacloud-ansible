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
module: zia_sandbox_rules
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
    preprocess_rule
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
        "id", "name", "description", "order", "rank", "enabled", "ba_rule_action",
        "first_time_enable", "first_time_operation", "ml_action_enabled",
        "by_threat_score", "ba_policy_categories", "url_categories", "protocols",
        "file_types", "locations", "location_groups", "departments", "groups", "users",
        "labels", "zpa_app_segments"
    ]

    # Only include attributes that are explicitly set in the playbook
    rule = {}
    for param in params:
        if param in module.params:
            rule[param] = module.params[param]

    module.debug(f"Initial parameters received (only explicitly set values): {rule}")

    rule_id = rule.get("id")
    rule_name = rule.get("name")

    existing_rule = None
    if rule_id is not None:
        module.debug(f"Fetching existing rule with ID: {rule_id}")
        result, _, error = client.sandbox_rules.get_rule(rule_id=rule_id)
        if error:
            module.fail_json(msg=f"Error fetching rule with id {rule_id}: {to_native(error)}")
        if result:
            existing_rule = result.as_dict()
            module.warn(f"Raw existing rule keys: {existing_rule.keys()}")
            module.warn(f"user_agent_types from API: {existing_rule.get('user_agent_types')}")
    else:
        module.debug(f"Listing rules to find by name: {rule_name}")
        result, _, error = client.sandbox_rules.list_rules()
        if error:
            module.fail_json(msg=f"Error listing rules: {to_native(error)}")
        if result:
            for rule_ in result:
                if rule_.name == rule_name:
                    existing_rule = rule_.as_dict()
                    module.debug(f"Found existing rule by name: {existing_rule}")
                    break

    # Normalize and compare
    desired_rule = normalize_rule(rule)

    for k in ["ba_policy_categories", "protocols", "file_types", "url_categories"]:
        if k in desired_rule and isinstance(desired_rule[k], list):
            desired_rule[k] = sorted(desired_rule[k])

    current_rule = normalize_rule(existing_rule) if existing_rule else {}

    for k in ["ba_policy_categories", "protocols", "file_types", "url_categories"]:
        if k in current_rule and isinstance(current_rule[k], list):
            current_rule[k] = sorted(current_rule[k])

    module.debug(f"Normalized desired rule: {desired_rule}")
    module.debug(f"Normalized current rule: {current_rule}")

    desired_rule_preprocessed = preprocess_rule(desired_rule, params)
    existing_rule_preprocessed = preprocess_rule(current_rule, params)
    module.debug(f"Preprocessed desired rule: {desired_rule_preprocessed}")
    module.debug(f"Preprocessed current rule: {existing_rule_preprocessed}")

    differences_detected = False
    list_attributes = [
        "ba_policy_categories", "url_categories", "protocols"
        "file_types", "locations", "location_groups", "departments", "groups", "users",
        "labels", "zpa_app_segments"
    ]

    # Attributes where order should be ignored
    order_agnostic_attributes = ["ba_policy_categories", "protocols", "file_types", "url_categories"]

    for key in params:
        desired_value = desired_rule_preprocessed.get(key)
        current_value = existing_rule_preprocessed.get(key)

        if key == "id" and desired_value is None and current_value is not None:
            continue

        if key == "enabled" and "state" in current_rule:
            current_value = current_rule["state"] == "ENABLED"

        # Special handling for list attributes - treat empty list and None as equivalent
        if key in list_attributes:
            if desired_value in (None, []) and current_value in (None, []):
                continue
            if desired_value is None:
                desired_value = []
            if current_value is None:
                current_value = []

        if isinstance(desired_value, list) and isinstance(current_value, list):
            if key in order_agnostic_attributes:
                # For order-agnostic attributes, compare sets instead of sorted lists
                if set(desired_value) != set(current_value):
                    differences_detected = True
                    module.warn(
                        f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
                    )
            else:
                # For other list attributes, maintain original comparison logic
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
        elif current_value != desired_value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
            )

    if module.check_mode:
        module.debug(f"Check mode - would {'create' if state == 'present' and not existing_rule else 'update' if differences_detected else 'delete' if state == 'absent' and existing_rule else 'do nothing'}")
        if state == "present" and (existing_rule is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_rule is not None:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    module.warn(f"Final payload being sent to SDK: {rule}")
    if state == "present":
        if existing_rule:
            if differences_detected:
                rule_id_to_update = existing_rule.get("id")
                if not rule_id_to_update:
                    module.fail_json(msg="Cannot update rule: ID is missing from the existing resource.")

                update_data = deleteNone({
                    "rule_id": existing_rule.get("id"),
                    "name": desired_rule.get("name"),
                    "description": desired_rule.get("description"),
                    "order": desired_rule.get("order"),
                    "rank": desired_rule.get("rank"),
                    "enabled": desired_rule.get("enabled"),
                    "ba_rule_action": desired_rule.get("ba_rule_action"),
                    "first_time_enable": desired_rule.get("first_time_enable"),
                    "first_time_operation": desired_rule.get("first_time_operation"),
                    "ml_action_enabled": desired_rule.get("ml_action_enabled"),
                    "by_threat_score": desired_rule.get("by_threat_score"),
                    "ba_policy_categories": desired_rule.get("ba_policy_categories"),
                    "url_categories": desired_rule.get("url_categories"),
                    "protocols": desired_rule.get("protocols"),
                    "file_types": desired_rule.get("file_types"),
                    "labels": desired_rule.get("labels"),
                    "locations": desired_rule.get("locations"),
                    "location_groups": desired_rule.get("location_groups"),
                    "departments": desired_rule.get("departments"),
                    "groups": desired_rule.get("groups"),
                    "users": desired_rule.get("users"),
                    "zpa_app_segments": desired_rule.get("zpa_app_segments"),
                })

                module.warn("Payload Update for SDK: {}".format(update_data))
                updated_rule, _, error = client.sandbox_rules.update_rule(
                    **update_data
                )
                if error:
                    module.fail_json(msg=f"Error updating rule: {to_native(error)}")
                module.exit_json(changed=True, data=updated_rule.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule)
        else:
            module.warn("Creating new rule as no existing rule found")
            """Create"""
            create_data = deleteNone({
                    "name": desired_rule.get("name"),
                    "description": desired_rule.get("description"),
                    "order": desired_rule.get("order"),
                    "rank": desired_rule.get("rank"),
                    "enabled": desired_rule.get("enabled"),
                    "ba_rule_action": desired_rule.get("ba_rule_action"),
                    "first_time_enable": desired_rule.get("first_time_enable"),
                    "first_time_operation": desired_rule.get("first_time_operation"),
                    "ml_action_enabled": desired_rule.get("ml_action_enabled"),
                    "by_threat_score": desired_rule.get("by_threat_score"),
                    "ba_policy_categories": desired_rule.get("ba_policy_categories"),
                    "url_categories": desired_rule.get("url_categories"),
                    "protocols": desired_rule.get("protocols"),
                    "file_types": desired_rule.get("file_types"),
                    "labels": desired_rule.get("labels"),
                    "locations": desired_rule.get("locations"),
                    "location_groups": desired_rule.get("location_groups"),
                    "departments": desired_rule.get("departments"),
                    "groups": desired_rule.get("groups"),
                    "users": desired_rule.get("users"),
                    "zpa_app_segments": desired_rule.get("zpa_app_segments"),
            })

            module.warn("Payload for SDK: {}".format(create_data))
            new_rule, _, error = client.sandbox_rules.add_rule(
                **create_data
            )
            if error:
                module.fail_json(msg=f"Error creating rule: {to_native(error)}")
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            rule_id_to_delete = existing_rule.get("id")
            if not rule_id_to_delete:
                module.fail_json(msg="Cannot delete rule: ID is missing from the existing resource.")

            module.debug(f"About to delete rule with ID: {rule_id_to_delete}")
            _, _, error = client.sandbox_rules.delete_rule(rule_id=rule_id_to_delete)
            if error:
                module.fail_json(msg=f"Error deleting rule: {to_native(error)}")
            module.debug(f"Successfully deleted rule with ID: {rule_id_to_delete}")
            module.exit_json(changed=True, data=existing_rule)
        else:
            module.debug("No rule found to delete")
            module.exit_json(changed=False, data={})

    else:
        module.debug(f"Unhandled state: {state}")
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
        first_time_enable=dict(type="bool", required=False),
        ml_action_enabled=dict(type="bool", required=False),
        by_threat_score=dict(type="int", required=False),
        url_categories=dict(type="list", elements="str", required=False),
        ba_policy_categories=dict(type="list", elements="str", required=False),
        protocols=dict(type="list", elements="str", required=False),
        file_types=dict(type="list", elements="str", required=False, choices=[
            "FTCATEGORY_BAT", "FTCATEGORY_APK", "FTCATEGORY_WINDOWS_SCRIPT_FILES",
            "FTCATEGORY_JAVA_APPLET", "FTCATEGORY_PDF_DOCUMENT", "FTCATEGORY_MS_RTF",
            "FTCATEGORY_FLASH", "FTCATEGORY_POWERSHELL", "FTCATEGORY_WINDOWS_LIBRARY",
            "FTCATEGORY_MS_EXCEL", "FTCATEGORY_HTA", "FTCATEGORY_VISUAL_BASIC_SCRIPT",
            "FTCATEGORY_MS_POWERPOINT", "FTCATEGORY_TAR", "FTCATEGORY_WINDOWS_EXECUTABLES",
            "FTCATEGORY_SCZIP", "FTCATEGORY_RAR", "FTCATEGORY_ZIP", "FTCATEGORY_P7Z",
            "FTCATEGORY_MICROSOFT_INSTALLER", "FTCATEGORY_BZIP2", "FTCATEGORY_PYTHON",
            "FTCATEGORY_MS_WORD",
            ]),
        first_time_operation=dict(
            type="str",
            required=False,
            choices=["ALLOW_SCAN", "QUARANTINE", "ALLOW_NOSCAN", "QUARANTINE_ISOLATE"]
        ),
        ba_rule_action=dict(
            type="str",
            required=False,
            choices=["ALLOW", "BLOCK"],
        ),
        labels=id_spec,
        locations=id_spec,
        location_groups=id_spec,
        departments=id_spec,
        groups=id_spec,
        users=id_spec,
        zpa_app_segments=id_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()