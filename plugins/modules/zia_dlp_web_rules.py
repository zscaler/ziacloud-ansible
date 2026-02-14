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
module: zia_dlp_web_rules
short_description: "Adds a new DLP policy rule"
description: "Adds a new DLP policy rule"
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
    description: "The unique identifier for the DLP policy rule."
    type: int
  name:
    description: "The DLP policy rule name."
    required: true
    type: str
  description:
    description: "The description of the DLP policy rule."
    required: false
    type: str
  order:
    description: "The rule order of execution for the DLP policy rule with respect to other rules."
    required: false
    type: int
  action:
    description: "The action taken when traffic matches the DLP policy rule criteria."
    required: false
    type: str
    choices:
        - ANY
        - BLOCK
        - ALLOW
        - ICAP_RESPONSE
  enabled:
    description:
        - Enables or disables the DLP policy rule.
    required: false
    type: bool
  protocols:
    description: "The protocol criteria specified for the DLP policy rule"
    required: false
    type: list
    elements: str
    choices:
        - ANY_RULE
        - FTP_RULE
        - HTTPS_RULE
        - HTTP_RULE
  rank:
    description: "The admin rank of the admin who created the DLP policy rule."
    required: false
    default: 7
    type: int
  locations:
    description: "The locations to which the DLP policy rule must be applied."
    type: list
    elements: int
    required: false
  location_groups:
    description: "The locations groups to which the DLP policy rule must be applied."
    type: list
    elements: int
    required: false
  departments:
    description: "The departments to which the DLP policy rule must be applied."
    type: list
    elements: int
    required: false
  groups:
    description: "The groups to which the DLP policy rule must be applied."
    type: list
    elements: int
    required: false
  users:
    description: "The users to which the DLP policy rule must be applied."
    type: list
    elements: int
    required: false
  url_categories:
    description: "The list of URL categories to which the DLP policy rule must be applied."
    type: list
    elements: int
    required: false
  dlp_engines:
    description: "The list of DLP engines to which the DLP policy rule must be applied."
    type: list
    elements: int
    required: false
  workload_groups:
    description: "The list of preconfigured workload groups to which the policy must be applied."
    type: list
    elements: int
    required: false
  include_domain_profiles:
    description:
      - "The list of domain profiles that must be added to the DLP rule criteria in order to apply the DLP rules."
      - "Only to domains that are part of the specified profiles."
      - "A maximum of 8 profiles can be selected."
    type: list
    elements: int
    required: false
  exclude_domain_profiles:
    description:
      - The list of domain profiles that must be added to the DLP rule criteria in order to apply the DLP rules.
      - It applies to all domains excluding the domains that are part of the specified profiles.
      - A maximum of 8 profiles can be selected.
    type: list
    elements: int
    required: false
  file_types:
    description: "The list of file types to which the DLP policy rule must be applied."
    required: false
    type: list
    elements: str
  cloud_applications:
    description: "The list of cloud applications to which the DLP policy rule must be applied."
    required: false
    type: list
    elements: str
  min_size:
    description: "The minimum file size (in KB) used for evaluation of the DLP policy rule.."
    required: false
    type: int
  time_windows:
    description: "The time windows to which the DLP policy rule must be applied."
    type: list
    elements: int
    required: false
  auditor:
    description: "The auditor to which the DLP policy rule must be applied."
    type: list
    elements: int
    required: false
  external_auditor_email:
    description:
        - The email address of an external auditor to whom DLP email notifications are sent..
    required: false
    type: str
  notification_template:
    description: "The template used for DLP notification emails."
    type: list
    elements: int
    required: false
  match_only:
    description: "The match only criteria for DLP engines."
    required: false
    type: bool
  icap_server:
    description: The DLP server using ICAP to which the transaction content is forwarded.
    type: list
    elements: int
    required: false
  without_content_inspection:
    description: "Indicates a DLP policy rule without content inspection, when the value is set to true."
    required: false
    type: bool
  labels:
    description: "The rule labels associated to the DLP policy rule."
    type: list
    elements: int
    required: false
  excluded_groups:
    description: "The groups that are excluded from the DLP policy rule."
    type: list
    elements: int
    required: false
  excluded_departments:
    description: "The departments that are excluded from the DLP policy rule."
    type: list
    elements: int
    required: false
  excluded_users:
    description: "The users that are excluded from the DLP policy rule."
    type: list
    elements: int
    required: false
  zscaler_incident_receiver:
    description: "Indicates whether a Zscaler Incident Receiver is associated to the DLP policy rule."
    required: false
    type: bool
    default: true
  severity:
    description: Indicates the severity selected for the DLP rule violation.
    required: false
    type: str
    default: RULE_SEVERITY_INFO
    choices:
        - RULE_SEVERITY_HIGH
        - RULE_SEVERITY_MEDIUM
        - RULE_SEVERITY_LOW
        - RULE_SEVERITY_INFO
  user_risk_score_levels:
    description: Indicates the user risk level selected for the DLP rule violation.
    required: false
    type: list
    elements: str
    choices:
        - LOW
        - MEDIUM
        - HIGH
        - CRITICAL
  parent_rule:
    description:
      - The unique identifier of the parent rule under which an exception rule is added.
    required: false
    type: int
  dlp_download_scan_enabled:
    description:
      - If this field is set to true, DLP scan is enabled for file downloads from cloud applications configured in the rule.
      - If this field is set to false, DLP scan is disabled for downloads from the cloud applications.
    required: false
    type: bool
  zcc_notifications_enabled:
    description:
      - If this field is set to true, Zscaler Client Connector notification is enabled for the block action triggered by the web DLP rule.
      - If this field is set to false, Zscaler Client Connector notification is disabled.
    required: false
    type: bool
  eun_template_id:
    description:
      - The EUN template ID associated with the rule
    required: false
    type: int
"""

EXAMPLES = r"""
- name: Create/Update/Delete DLP Web Rules
  zscaler.ziacloud.zia_dlp_web_rules:
    provider: '{{ provider }}'
    name: "Example"
    description: "Example"
    action: "ALLOW"
    enabled: true
    without_content_inspection: false
    zscaler_incident_receiver: false
    order: 1
    rank: 7
    user_risk_score_levels:
      - CRITICAL
      - HIGH
      - LOW
      - MEDIUM
    protocols:
      - FTP_RULE
      - HTTPS_RULE
      - HTTP_RULE
    min_size: 0
    cloud_applications:
      - WINDOWS_LIVE_HOTMAIL
    file_types:
      - "ASM"
      - "MATLAB_FILES"
      - "SAS"
      - "SCALA"
    locations:
      - 61188118
      - 61188119
    groups:
      - 76662385
      - 76662401
    users:
      - 45513075
      - 76676944
    departments:
      - 45513014
      - 76676875
"""

RETURN = r"""
# Returns information on a specified ZIA Admin User.
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


def normalize_dlp_rule(rule):
    """Normalize rule data by removing computed values."""
    if not rule:
        return {}

    normalized = rule.copy()
    computed_values = []
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def get_external_dlp_engine_id(client):
    """Get the ID of the EXTERNAL DLP engine using list_dlp_engines_lite."""
    # Search specifically for EXTERNAL engine
    engines, _unused, error = client.dlp_engine.list_dlp_engines_lite(query_params={"search": "EXTERNAL"})
    if error:
        raise Exception(f"Failed to search DLP engines: {to_native(error)}")

    if not engines:
        # Fallback to full list if search didn't work
        engines, _unused, error = client.dlp_engine.list_dlp_engines_lite()
        if error:
            raise Exception(f"Failed to list DLP engines: {to_native(error)}")

    # Find EXTERNAL engine by predefined_engine_name
    for engine in engines:
        if hasattr(engine, "predefined_engine_name") and str(engine.predefined_engine_name).upper() == "EXTERNAL":
            return engine.id

    raise Exception("EXTERNAL DLP engine not found. Please ensure your account has access to the EXTERNAL DLP engine")


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)

    params = [
        "id",
        "name",
        "description",
        "order",
        "protocols",
        "rank",
        "locations",
        "location_groups",
        "groups",
        "departments",
        "users",
        "url_categories",
        "dlp_engines",
        "file_types",
        "cloud_applications",
        "min_size",
        "action",
        "enabled",
        "time_windows",
        "auditor",
        "external_auditor_email",
        "notification_template",
        "match_only",
        "icap_server",
        "without_content_inspection",
        "labels",
        "excluded_groups",
        "excluded_departments",
        "excluded_users",
        "zscaler_incident_receiver",
        "dlp_download_scan_enabled",
        "zcc_notifications_enabled",
        "user_risk_score_levels",
        "severity",
        "parent_rule",
        "workload_groups",
        "include_domain_profiles",
        "exclude_domain_profiles",
        "eun_template_id",
    ]

    rule = {param: module.params.get(param) for param in params}

    # Initialize file_types as empty list if None
    rule["file_types"] = rule.get("file_types") or []

    # Handle without_content_inspection logic
    without_content_inspection = rule.get("without_content_inspection", False)
    if without_content_inspection:
        try:
            # Automatically set dlp_engines to EXTERNAL (requirements 1b and 2c)
            rule["dlp_engines"] = [get_external_dlp_engine_id(client)]

            # If user hasn't explicitly set file_types, set to FTCATEGORY_ALL_OUTBOUND (requirements 1a and 2b)
            if not module.params.get("file_types"):
                rule["file_types"] = ["FTCATEGORY_ALL_OUTBOUND"]
        except Exception as e:
            module.fail_json(
                msg=f"Error configuring for without_content_inspection: {to_native(e)}",
                exception=format_exc(),
            )
    # When without_content_inspection is false, both fields are optional (requirement 3)
    # No validation needed here as per requirements

    rule_id = rule.get("id")
    rule_name = rule.get("name")

    existing_rule = None
    if rule_id is not None:
        result, _unused, error = client.dlp_web_rules.get_rule(rule_id=rule_id)
        if error:
            module.fail_json(msg=f"Error fetching rule with id {rule_id}: {to_native(error)}")
        if result:
            existing_rule = result.as_dict()
    else:
        result, _unused, error = client.dlp_web_rules.list_rules()
        if error:
            module.fail_json(msg=f"Error listing rules: {to_native(error)}")
        if result:
            for rule_ in result:
                if rule_.name == rule_name:
                    existing_rule = rule_.as_dict()
                    break

    # Normalize and compare rules
    desired_rule = normalize_dlp_rule(rule)
    current_rule = normalize_dlp_rule(existing_rule) if existing_rule else {}

    def preprocess_rule(rule_dict, params):
        """Preprocess rule attributes for comparison."""
        processed = rule_dict.copy()
        for attr in params:
            if attr in processed:
                value = processed[attr]

                # Handle list attributes
                if isinstance(value, list):
                    if all(isinstance(item, dict) and "id" in item for item in value):
                        processed[attr] = [item["id"] for item in value]
                    else:
                        processed[attr] = sorted(value)

                # Handle icap_server dictionary
                elif isinstance(value, dict) and attr == "icap_server":
                    processed[attr] = value.get("id", {})

                # Set defaults for certain attributes
                elif attr == "min_size" and value is None:
                    processed[attr] = 0
                elif attr in [
                    "match_only",
                    "dlp_download_scan_enabled",
                    "zcc_notifications_enabled",
                    "zscaler_incident_receiver",
                ]:
                    if value is None:
                        processed[attr] = False

        return processed

    desired_processed = preprocess_rule(desired_rule, params)
    current_processed = preprocess_rule(current_rule, params)

    # List of attributes where empty list and None should be treated as equivalent
    list_attributes = [
        "locations",
        "location_groups",
        "groups",
        "departments",
        "users",
        "url_categories",
        "dlp_engines",
        "file_types",
        "cloud_applications",
        "time_windows",
        "labels",
        "excluded_groups",
        "excluded_departments",
        "excluded_users",
        "workload_groups",
        "include_domain_profiles",
        "exclude_domain_profiles",
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
            if all(isinstance(x, int) for x in desired_value) and all(isinstance(x, int) for x in current_value):
                desired_value = sorted(desired_value)
                current_value = sorted(current_value)

        if current_value != desired_value:
            differences_detected = True
            module.warn(f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}")

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
                    module.fail_json(msg="Cannot update rule: ID is missing from the existing resource.")

                update_data = deleteNone(
                    {
                        "rule_id": existing_rule.get("id"),
                        "name": desired_rule.get("name"),
                        "description": desired_rule.get("description"),
                        "order": desired_rule.get("order"),
                        "rank": desired_rule.get("rank"),
                        "action": desired_rule.get("action"),
                        "enabled": desired_rule.get("enabled"),
                        "protocols": desired_rule.get("protocols"),
                        "locations": desired_rule.get("locations"),
                        "location_groups": desired_rule.get("location_groups"),
                        "groups": desired_rule.get("groups"),
                        "departments": desired_rule.get("departments"),
                        "users": desired_rule.get("users"),
                        "url_categories": desired_rule.get("url_categories"),
                        "dlp_engines": desired_rule.get("dlp_engines"),
                        "file_types": desired_rule.get("file_types"),
                        "cloud_applications": desired_rule.get("cloud_applications"),
                        "min_size": desired_rule.get("min_size"),
                        "time_windows": desired_rule.get("time_windows"),
                        "auditor": desired_rule.get("auditor"),
                        "external_auditor_email": desired_rule.get("external_auditor_email"),
                        "notification_template": desired_rule.get("notification_template"),
                        "match_only": desired_rule.get("match_only"),
                        "icap_server": desired_rule.get("icap_server"),
                        "without_content_inspection": desired_rule.get("without_content_inspection"),
                        "labels": desired_rule.get("labels"),
                        "excluded_groups": desired_rule.get("excluded_groups"),
                        "excluded_departments": desired_rule.get("excluded_departments"),
                        "excluded_users": desired_rule.get("excluded_users"),
                        "zscaler_incident_receiver": desired_rule.get("zscaler_incident_receiver"),
                        "dlp_download_scan_enabled": desired_rule.get("dlp_download_scan_enabled"),
                        "zcc_notifications_enabled": desired_rule.get("zcc_notifications_enabled"),
                        "eun_template_id": desired_rule.get("eun_template_id"),
                        "user_risk_score_levels": desired_rule.get("user_risk_score_levels"),
                        "severity": desired_rule.get("severity"),
                        "parent_rule": desired_rule.get("parent_rule"),
                        "workload_groups": desired_rule.get("workload_groups"),
                        "include_domain_profiles": desired_rule.get("include_domain_profiles"),
                        "exclude_domain_profiles": desired_rule.get("exclude_domain_profiles"),
                    }
                )

                module.warn("Payload Update for SDK: {}".format(update_data))
                updated_rule, _unused, error = client.dlp_web_rules.update_rule(**update_data)
                if error:
                    module.fail_json(msg=f"Error updating rule: {to_native(error)}")
                module.exit_json(changed=True, data=updated_rule.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule)
        else:
            create_data = deleteNone(
                {
                    "name": desired_rule.get("name"),
                    "description": desired_rule.get("description"),
                    "order": desired_rule.get("order"),
                    "rank": desired_rule.get("rank"),
                    "action": desired_rule.get("action"),
                    "enabled": desired_rule.get("enabled"),
                    "protocols": desired_rule.get("protocols"),
                    "locations": desired_rule.get("locations"),
                    "location_groups": desired_rule.get("location_groups"),
                    "groups": desired_rule.get("groups"),
                    "departments": desired_rule.get("departments"),
                    "users": desired_rule.get("users"),
                    "url_categories": desired_rule.get("url_categories"),
                    "dlp_engines": desired_rule.get("dlp_engines"),
                    "file_types": desired_rule.get("file_types"),
                    "cloud_applications": desired_rule.get("cloud_applications"),
                    "min_size": desired_rule.get("min_size"),
                    "time_windows": desired_rule.get("time_windows"),
                    "auditor": desired_rule.get("auditor"),
                    "external_auditor_email": desired_rule.get("external_auditor_email"),
                    "notification_template": desired_rule.get("notification_template"),
                    "match_only": desired_rule.get("match_only"),
                    "icap_server": desired_rule.get("icap_server"),
                    "without_content_inspection": desired_rule.get("without_content_inspection"),
                    "labels": desired_rule.get("labels"),
                    "excluded_groups": desired_rule.get("excluded_groups"),
                    "excluded_departments": desired_rule.get("excluded_departments"),
                    "excluded_users": desired_rule.get("excluded_users"),
                    "zscaler_incident_receiver": desired_rule.get("zscaler_incident_receiver"),
                    "dlp_download_scan_enabled": desired_rule.get("dlp_download_scan_enabled"),
                    "zcc_notifications_enabled": desired_rule.get("zcc_notifications_enabled"),
                    "eun_template_id": desired_rule.get("eun_template_id"),
                    "user_risk_score_levels": desired_rule.get("user_risk_score_levels"),
                    "severity": desired_rule.get("severity"),
                    "parent_rule": desired_rule.get("parent_rule"),
                    "workload_groups": desired_rule.get("workload_groups"),
                    "include_domain_profiles": desired_rule.get("include_domain_profiles"),
                    "exclude_domain_profiles": desired_rule.get("exclude_domain_profiles"),
                }
            )
            module.warn("Payload Update for SDK: {}".format(create_data))
            new_rule, _unused, error = client.dlp_web_rules.add_rule(**create_data)
            if error:
                module.fail_json(msg=f"Error creating rule: {to_native(error)}")
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            rule_id_to_delete = existing_rule.get("id")
            if not rule_id_to_delete:
                module.fail_json(msg="Cannot delete rule: ID is missing from the existing resource.")

            _unused, _unused, error = client.dlp_web_rules.delete_rule(rule_id=rule_id_to_delete)
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
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        enabled=dict(type="bool", required=False),
        order=dict(type="int", required=False),
        rank=dict(type="int", required=False, default=7),
        locations=id_spec,
        location_groups=id_spec,
        groups=id_spec,
        departments=id_spec,
        users=id_spec,
        labels=id_spec,
        time_windows=id_spec,
        dlp_engines=id_spec,
        auditor=id_spec,
        notification_template=id_spec,
        excluded_groups=id_spec,
        excluded_departments=id_spec,
        excluded_users=id_spec,
        workload_groups=id_spec,
        include_domain_profiles=id_spec,
        exclude_domain_profiles=id_spec,
        protocols=dict(
            type="list",
            elements="str",
            required=False,
            choices=["ANY_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"],
        ),
        url_categories=dict(type="list", elements="int", required=False),
        cloud_applications=dict(type="list", elements="str", required=False),
        external_auditor_email=dict(type="str", required=False),
        min_size=dict(type="int", required=False),
        parent_rule=dict(type="int", required=False),
        match_only=dict(type="bool", required=False),
        without_content_inspection=dict(type="bool", required=False),
        zscaler_incident_receiver=dict(type="bool", default=True, required=False),
        zcc_notifications_enabled=dict(type="bool", required=False),
        dlp_download_scan_enabled=dict(type="bool", required=False),
        icap_server=dict(type="list", elements="int", required=False),
        eun_template_id=dict(type="int", required=False),
        action=dict(
            type="str",
            required=False,
            choices=["ANY", "BLOCK", "ALLOW", "ICAP_RESPONSE"],
        ),
        user_risk_score_levels=dict(
            type="list",
            elements="str",
            required=False,
            choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        ),
        severity=dict(
            type="str",
            default="RULE_SEVERITY_INFO",
            required=False,
            choices=[
                "RULE_SEVERITY_HIGH",
                "RULE_SEVERITY_MEDIUM",
                "RULE_SEVERITY_LOW",
                "RULE_SEVERITY_INFO",
            ],
        ),
        file_types=dict(
            type="list",
            elements="str",
            required=False,
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
