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
short_description: "Adds a Sandbox policy rule"
description: "Adds a Sandbox policy rule"
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
    description: "Unique identifier for the Sandbox Rule"
    required: false
    type: int
  name:
    description: "Name of the Sandbox Rule"
    required: true
    type: str
  description:
    description: "Additional information about the rule"
    required: false
    type: str
  enabled:
    description:
        - Determines whether the Sandbox Rule is enabled or disabled
    required: false
    type: bool
  order:
    description: "Rule order number of the Sandbox Rule"
    required: false
    type: int
  rank:
    description: "Admin rank of the Sandbox Rule"
    required: false
    default: 7
    type: int
  ml_action_enabled:
    description:
      - Indicates whether to enable or disable the AI Instant Verdict option
      - To have the Zscaler service use AI analysis to instantly assign threat scores to unknown files.
      - This option is available to use only with specific rule actions such as Quarantine and Allow and Scan for First-Time Action.
    required: false
    type: bool
  first_time_enable:
    description:
      - Indicates whether a First-Time Action is specifically configured for the rule.
      - The First-Time Action takes place when users download unknown files.
      - The action to be applied is specified using the firstTimeOperation field.
    required: false
    type: bool
  by_threat_score:
    description: Minimum threat score can be set between 40 to 70
    required: false
    type: int
  first_time_operation:
    description: The action that must take place when users download unknown files for the first time
    required: false
    type: str
    choices:
        - ALLOW_SCAN
        - QUARANTINE
        - ALLOW_NOSCAN
        - QUARANTINE_ISOLATE
  ba_rule_action:
    description: The action configured for the rule that must take place if the traffic matches the rule criteria
    required: false
    type: str
    choices:
        - ALLOW
        - BLOCK
  protocols:
    description: The protocols to which the rule applies
    required: false
    type: list
    elements: str
    choices:
        - FOHTTP_RULE
        - FTP_RULE
        - HTTPS_RULE
        - HTTP_RULE
  ba_policy_categories:
    description: The threat categories to which the rule applies
    required: false
    type: list
    elements: str
    choices:
        - ADWARE_BLOCK
        - BOTMAL_BLOCK
        - ANONYP2P_BLOCK
        - RANSOMWARE_BLOCK
        - OFFSEC_TOOLS_BLOCK
        - SUSPICIOUS_BLOCK
  file_types:
    description: The threat categories to which the rule applies
    required: false
    type: list
    elements: str
    choices:
        - FTCATEGORY_BAT
        - FTCATEGORY_APK
        - FTCATEGORY_WINDOWS_SCRIPT_FILES
        - FTCATEGORY_JAVA_APPLET
        - FTCATEGORY_PDF_DOCUMENT
        - FTCATEGORY_MS_RTF
        - FTCATEGORY_FLASH
        - FTCATEGORY_POWERSHELL
        - FTCATEGORY_WINDOWS_LIBRARY
        - FTCATEGORY_MS_EXCEL
        - FTCATEGORY_HTA
        - FTCATEGORY_VISUAL_BASIC_SCRIPT
        - FTCATEGORY_MS_POWERPOINT
        - FTCATEGORY_TAR
        - FTCATEGORY_WINDOWS_EXECUTABLES
        - FTCATEGORY_SCZIP
        - FTCATEGORY_RAR
        - FTCATEGORY_ZIP
        - FTCATEGORY_P7Z
        - FTCATEGORY_MICROSOFT_INSTALLER
        - FTCATEGORY_BZIP2
        - FTCATEGORY_PYTHON
        - FTCATEGORY_MS_WORD
        - FTCATEGORY_ISO
        - FTCATEGORY_DMG
        - FTCATEGORY_JPEG
        - FTCATEGORY_PNG
  url_categories:
    description:
      - The URL categories to which the rule applies
      - Use the info resource zia_url_categories_info to retrieve the category names.
    required: false
    type: list
    elements: str
  locations:
    description: "The locations to which the Sandbox Rule applies"
    type: list
    elements: int
    required: false
  location_groups:
    description: "The location groups to which the Sandbox Rule applies"
    type: list
    elements: int
    required: false
  departments:
    description: "The departments to which the Sandbox Rule applies"
    type: list
    elements: int
    required: false
  groups:
    description: "The groups to which the Sandbox Rule applies"
    type: list
    elements: int
    required: false
  users:
    description: "The users to which the Sandbox Rule applies"
    type: list
    elements: int
    required: false
  labels:
    description: "Labels that are applicable to the rule."
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
        required: false
      name:
        description: The name of the Application Segment
        type: str
        required: false
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
    preprocess_rule,
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
        "enabled",
        "ba_rule_action",
        "first_time_enable",
        "first_time_operation",
        "ml_action_enabled",
        "by_threat_score",
        "ba_policy_categories",
        "url_categories",
        "protocols",
        "file_types",
        "locations",
        "location_groups",
        "departments",
        "groups",
        "users",
        "labels",
        "zpa_app_segments",
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
        result, _unused, error = client.sandbox_rules.get_rule(rule_id=rule_id)
        if error:
            module.fail_json(
                msg=f"Error fetching rule with id {rule_id}: {to_native(error)}"
            )
        if result:
            existing_rule = result.as_dict()
            module.warn(f"Raw existing rule keys: {existing_rule.keys()}")
            module.warn(
                f"user_agent_types from API: {existing_rule.get('user_agent_types')}"
            )
    else:
        module.debug(f"Listing rules to find by name: {rule_name}")
        result, _unused, error = client.sandbox_rules.list_rules()
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
        "ba_policy_categories",
        "url_categories",
        "protocols",
        "file_types",
        "locations",
        "location_groups",
        "departments",
        "groups",
        "users",
        "labels",
        "zpa_app_segments",
    ]

    # Attributes where order should be ignored
    order_agnostic_attributes = [
        "ba_policy_categories",
        "protocols",
        "file_types",
        "url_categories",
    ]

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
        if state == "present" and not existing_rule:
            action = "create"
        elif differences_detected:
            action = "update"
        elif state == "absent" and existing_rule:
            action = "delete"
        else:
            action = "do nothing"

        module.debug(f"Check mode - would {action}")

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
                    module.fail_json(
                        msg="Cannot update rule: ID is missing from the existing resource."
                    )

                update_data = deleteNone(
                    {
                        "rule_id": existing_rule.get("id"),
                        "name": desired_rule.get("name"),
                        "description": desired_rule.get("description"),
                        "order": desired_rule.get("order"),
                        "rank": desired_rule.get("rank"),
                        "enabled": desired_rule.get("enabled"),
                        "ba_rule_action": desired_rule.get("ba_rule_action"),
                        "first_time_enable": desired_rule.get("first_time_enable"),
                        "first_time_operation": desired_rule.get(
                            "first_time_operation"
                        ),
                        "ml_action_enabled": desired_rule.get("ml_action_enabled"),
                        "by_threat_score": desired_rule.get("by_threat_score"),
                        "ba_policy_categories": desired_rule.get(
                            "ba_policy_categories"
                        ),
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
                    }
                )

                module.warn("Payload Update for SDK: {}".format(update_data))
                updated_rule, _unused, error = client.sandbox_rules.update_rule(
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
            create_data = deleteNone(
                {
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
                }
            )

            module.warn("Payload for SDK: {}".format(create_data))
            new_rule, _unused, error = client.sandbox_rules.add_rule(**create_data)
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

            module.debug(f"About to delete rule with ID: {rule_id_to_delete}")
            _unused, _unused, error = client.sandbox_rules.delete_rule(
                rule_id=rule_id_to_delete
            )
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
    external_id_name_dict_spec = dict(
        external_id=dict(type="str", required=False),
        name=dict(type="str", required=False),
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
        first_time_enable=dict(type="bool", required=False),
        ml_action_enabled=dict(type="bool", required=False),
        by_threat_score=dict(type="int", required=False),
        url_categories=dict(type="list", elements="str", required=False),
        ba_policy_categories=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "ADWARE_BLOCK",
                "BOTMAL_BLOCK",
                "ANONYP2P_BLOCK",
                "RANSOMWARE_BLOCK",
                "OFFSEC_TOOLS_BLOCK",
                "SUSPICIOUS_BLOCK",
            ],
        ),
        protocols=dict(
            type="list",
            elements="str",
            required=False,
            choices=["FOHTTP_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"],
        ),
        file_types=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "FTCATEGORY_BAT",
                "FTCATEGORY_APK",
                "FTCATEGORY_WINDOWS_SCRIPT_FILES",
                "FTCATEGORY_JAVA_APPLET",
                "FTCATEGORY_PDF_DOCUMENT",
                "FTCATEGORY_MS_RTF",
                "FTCATEGORY_FLASH",
                "FTCATEGORY_POWERSHELL",
                "FTCATEGORY_WINDOWS_LIBRARY",
                "FTCATEGORY_MS_EXCEL",
                "FTCATEGORY_HTA",
                "FTCATEGORY_VISUAL_BASIC_SCRIPT",
                "FTCATEGORY_MS_POWERPOINT",
                "FTCATEGORY_TAR",
                "FTCATEGORY_WINDOWS_EXECUTABLES",
                "FTCATEGORY_SCZIP",
                "FTCATEGORY_RAR",
                "FTCATEGORY_ZIP",
                "FTCATEGORY_P7Z",
                "FTCATEGORY_MICROSOFT_INSTALLER",
                "FTCATEGORY_BZIP2",
                "FTCATEGORY_PYTHON",
                "FTCATEGORY_MS_WORD",
                "FTCATEGORY_ISO",
                "FTCATEGORY_DMG",
                "FTCATEGORY_JPEG",
                "FTCATEGORY_PNG",
            ],
        ),
        first_time_operation=dict(
            type="str",
            required=False,
            choices=["ALLOW_SCAN", "QUARANTINE", "ALLOW_NOSCAN", "QUARANTINE_ISOLATE"],
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
        zpa_app_segments=external_id_name_list_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
