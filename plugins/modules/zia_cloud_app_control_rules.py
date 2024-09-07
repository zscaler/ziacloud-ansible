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
module: zia_cloud_app_control_rules
short_description: "Adds a new Cloud App Control rule."
description: "Adds a new Cloud App Control rule."
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
    description: "Unique identifier for the Cloud App Control policy rule"
    required: false
    type: int
  name:
    description: "Name of the Cloud App Control policy rule"
    required: true
    type: str
  description:
    description: "Additional information about the rule"
    required: false
    type: str
  enabled:
    description:
        - Determines whether the Cloud App Control rule is enabled or disabled
    required: false
    type: bool
  order:
    description: "Rule order number of the Cloud App Control policy rule"
    required: false
    type: int
  rule_type:
    description:
        - The rule type selected from the available options.
    required: true
    type: str
    choices:
      - SOCIAL_NETWORKING
      - STREAMING_MEDIA
      - WEBMAIL
      - INSTANT_MESSAGING
      - BUSINESS_PRODUCTIVITY
      - ENTERPRISE_COLLABORATION
      - SALES_AND_MARKETING
      - SYSTEM_AND_DEVELOPMENT
      - CONSUMER
      - HOSTING_PROVIDER
      - IT_SERVICES
      - FILE_SHARE
      - DNS_OVER_HTTPS
      - HUMAN_RESOURCES
      - LEGAL
      - HEALTH_CARE
      - FINANCE
      - CUSTOM_CAPP
      - AI_ML
  actions:
    description:
      - Actions allowed for the specified type.
    type: list
    elements: str
    required: false
  applications:
    description:
        - List of cloud applications for which rule will be applied
    type: list
    elements: str
    required: false
  locations:
    description:
        - Name-ID pairs of locations for which rule must be applied
    type: list
    elements: int
    required: false
  groups:
    description:
        - Name-ID pairs of groups for which rule must be applied
    type: list
    elements: int
    required: false
  departments:
    description:
        - Name-ID pairs of departments for which rule will be applied
    type: list
    elements: int
    required: false
  users:
    description:
        - Name-ID pairs of users for which rule must be applied
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
  time_windows:
    description:
        - Name-ID pairs of time interval during which rule must be enforced.
    type: list
    elements: int
    required: false
  cloud_app_risk_profile:
    description:
      - Name-ID pair of cloud Application Risk Profile for which rule will be applied.
    type: list
    elements: int
    required: false
  tenancy_profile_ids:
    description:
      - Name-ID pair of Tenant Profile for which rule will be applied.
    type: list
    elements: int
    required: false
  cloud_app_instances:
    description:
      - Name-ID pair of Cloud application instances for which rule will be applied.
    type: list
    elements: int
    required: false
  rank:
    description:
        - Admin rank of the admin who creates this rule
    required: false
    default: 7
    type: int
  user_agent_types:
    description:
        - Any number of user agents to which the rule applies.
    type: list
    elements: str
    required: false
    choices:
        - OPERA
        - FIREFOX
        - MSIE
        - MSEDGE
        - CHROME
        - SAFARI
        - OTHER
        - MSCHREDGE
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
  time_quota:
    description:
        - Action must be set to CAUTION
        - Time quota in minutes, after which the Cloud App Control rule is applied.
        - The allowed range is between 15 minutes and 600 minutes.
        - If not set, no quota is enforced. If a policy rule action is set to BLOCK, this field is not applicable.
    required: false
    type: int
  size_quota:
    description:
        - Action must be set to CAUTION
        - Size quota in MB beyond which the Cloud App Control rule is applied.
        - The allowed range is between 10 MB and 100000 MB
        - If not set, no quota is enforced. If a policy rule action is set to BLOCK, this field is not applicable.
    required: false
    type: int
  location_groups:
    description:
        - Name-ID pairs of the location groups to which the rule must be applied.
    type: list
    elements: int
    required: false
  labels:
    description:
        - The Cloud App Control rule label. Rule labels allow you to logically group your organization policy rules.
        - Policy rules that are not associated with a rule label are grouped under the Untagged label.
    type: list
    elements: int
    required: false
  enforce_time_validity:
    description:
        - Enforce a set a validity time period for the Cloud App Control rule.
    type: bool
  validity_start_time:
    description:
      - If enforce_time_validity is set to true, the Cloud App Control rule will be valid starting on this date and time.
      - Example ( 11/20/2023 11:59 PM )
      - Notice that validity_start_time cannot be in the past
    required: false
    type: str
  validity_time_zone_id:
    description:
      - If enforceTimeValidity is set to true, the Cloud App Control rule date and time is valid based on this time zone ID.
    required: false
    type: str
  validity_end_time:
    description:
      - If enforce_time_validity is set to true, the Cloud App Control rule will cease to be valid on this end date and time.
      - Example ( 12/21/2023 12:00 AM )
    required: false
    type: str
  cascading_enabled:
    description:
        - Enforce the URL Filtering policy on a transaction, even after it is explicitly allowed by the Cloud App Control policy.
        - The URL Filtering policy does not apply if the transaction is blocked by the Cloud App Control policy.
    type: bool
  cbi_profile:
      description:
        - The cloud browser isolation profile to which the ISOLATE action is applied in the Cloud App Control Policy rules.
        - This parameter is required for the ISOLATE action and is not applicable to other actions.
      type: dict
      suboptions:
          id:
              description:
                  - The universally unique identifier (UUID) for the browser isolation profile.
              type: str
              required: True
          name:
              description:
                  - Name of the browser isolation profile.
              type: str
              required: True
          url:
              description:
                  - The browser isolation profile URL.
              type: str
              required: True
"""

EXAMPLES = r"""
- name: Create/Update/Delete a Cloud App Control Rule.
  zscaler.ziacloud.zia_cloud_app_control_rules:
    provider: '{{ provider }}'
    name: "Example_WebMail_Rule"
    description: "Example_WebMail_Rule"
    enabled: true
    order: 1
    actions:
        - ALLOW_WEBMAIL_VIEW
        - ALLOW_WEBMAIL_ATTACHMENT_SEND
        - ALLOW_WEBMAIL_SEND
    applications:
      - "GOOGLE_WEBMAIL"
      - "YAHOO_WEBMAIL"
"""

RETURN = r"""
# The newly created Cloud App Control Rule resource record.
"""

import time
from datetime import datetime
from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
    normalize_boolean_attributes,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)

try:
    import pytz

    HAS_PYTZ = True
    PYTZ_IMPORT_ERROR = None  # Explicitly set to None when import is successful
except ImportError:
    pytz = None  # Set to None to indicate the module is unavailable
    HAS_PYTZ = False
    PYTZ_IMPORT_ERROR = missing_required_lib(
        "pytz"
    )  # Use missing_required_lib for better error messages


def validate_and_convert_time_fields(rule):
    if not HAS_PYTZ:
        raise ImportError(
            PYTZ_IMPORT_ERROR
        )  # Properly handle the case where pytz is not available

    enforce_time_validity = rule.get("enforce_time_validity")
    if enforce_time_validity:
        for field in [
            "validity_start_time",
            "validity_end_time",
            "validity_time_zone_id",
        ]:
            if not rule.get(field):
                raise ValueError(
                    f"'{field}' must be set when 'enforce_time_validity' is True"
                )

        timezone_id = rule["validity_time_zone_id"]
        if timezone_id not in pytz.all_timezones:
            raise ValueError(f"Invalid timezone ID: {timezone_id}")

        for time_field in ["validity_start_time", "validity_end_time"]:
            time_str = rule.get(time_field)
            if time_str:
                time_obj = datetime.strptime(time_str, "%m/%d/%Y %I:%M %p")
                timezone = pytz.timezone(timezone_id)
                time_with_tz = timezone.localize(time_obj)
                rule[time_field] = int(time.mktime(time_with_tz.timetuple()))


def validate_additional_fields(rule):
    """
    Validates additional fields in the rule.
    """

    # Validate time_quota
    time_quota = rule.get("time_quota")
    if time_quota and (time_quota < 15 or time_quota > 600):
        raise ValueError("time_quota must be within the range of 15 to 600 minutes")

    # Validate and convert size_quota from MB to KB
    size_quota_mb = rule.get("size_quota")
    if size_quota_mb:
        if size_quota_mb < 10 or size_quota_mb > 100000:
            raise ValueError(
                "size_quota must be within the range of 10 MB to 100000 MB"
            )
        # Convert MB to KB for API
        rule["size_quota"] = size_quota_mb * 1024


def normalize_rule(rule):
    """
    Normalize rule data by setting computed values.
    """
    if not rule:
        return {}

    normalized = rule.copy()

    # Add 'profile_seq' to the list of computed values to be removed
    computed_values = ["profile_seq"]
    for attr in computed_values:
        if (
            "cbi_profile" in normalized
            and isinstance(normalized["cbi_profile"], dict)
            and attr in normalized["cbi_profile"]
        ):
            normalized["cbi_profile"].pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    rule = dict()
    params = [
        "id",
        "name",
        "description",
        "actions",
        "type",  # This will store the value from rule_type
        "order",
        "protocols",
        "locations",
        "groups",
        "departments",
        "users",
        "enabled",
        "time_windows",
        "rank",
        "applications",
        "cloud_app_instances",
        "tenancy_profile_ids",
        "cloud_app_risk_profile",
        "time_quota",
        "size_quota",
        "location_groups",
        "labels",
        "validity_start_time",
        "validity_end_time",
        "validity_time_zone_id",
        "enforce_time_validity",
        "actions",
        "cascading_enabled",
        "user_agent_types",
        "device_trust_levels",
        "device_groups",
        "devices",
        "user_risk_score_levels",
        "cbi_profile",
    ]

    # Map rule_type to type in the payload
    rule["type"] = module.params.get("rule_type", None)

    for param_name in params:
        if param_name != "type":  # Skip because it's already handled above
            rule[param_name] = module.params.get(param_name, None)

    # Normalize boolean attributes
    bool_attributes = ["enforce_time_validity", "cascading_enabled"]
    rule = normalize_boolean_attributes(rule, bool_attributes)

    # Add the validation and conversion logic here
    validate_and_convert_time_fields(rule)

    # Validate and convert additional fields
    validate_additional_fields(rule)

    rule_id = rule.get("id", None)
    rule_name = rule.get("name", None)
    rule_type = rule.get("type", None)  # Use the mapped type

    existing_rule = None
    if rule_id is not None:
        ruleBox = client.cloudappcontrol.get_rule(rule_type=rule_type, rule_id=rule_id)
        if ruleBox is not None:
            existing_rule = ruleBox.to_dict()
    elif rule_name is not None:
        rules = client.cloudappcontrol.list_rules(rule_type=rule_type).to_list()
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

    if module.check_mode:
        # If in check mode, report changes and exit
        if state == "present" and (existing_rule is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_rule is not None:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

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
                        rule_id=existing_rule.get("id", ""),
                        name=existing_rule.get("name", ""),
                        description=existing_rule.get("description", ""),
                        enabled=existing_rule.get("enabled", ""),
                        actions=existing_rule.get("actions", ""),
                        type=existing_rule.get("type", ""),
                        order=existing_rule.get("order", ""),
                        locations=existing_rule.get("locations", ""),
                        groups=existing_rule.get("groups", ""),
                        departments=existing_rule.get("departments", ""),
                        users=existing_rule.get("users", ""),
                        device_groups=existing_rule.get("device_groups", ""),
                        devices=existing_rule.get("devices", ""),
                        time_windows=existing_rule.get("time_windows", ""),
                        rank=existing_rule.get("rank", ""),
                        applications=existing_rule.get("applications", ""),
                        tenancy_profile_ids=existing_rule.get(
                            "tenancy_profile_ids", ""
                        ),
                        cloud_app_risk_profile=existing_rule.get(
                            "cloud_app_risk_profile", ""
                        ),
                        cloud_app_instances=existing_rule.get(
                            "cloud_app_instances", ""
                        ),
                        cascading_enabled=existing_rule.get("cascading_enabled", ""),
                        time_quota=existing_rule.get("time_quota", ""),
                        size_quota=existing_rule.get("size_quota", ""),
                        location_groups=existing_rule.get("location_groups", ""),
                        labels=existing_rule.get("labels", ""),
                        validity_start_time=existing_rule.get(
                            "validity_start_time", ""
                        ),
                        validity_end_time=existing_rule.get("validity_end_time", ""),
                        validity_time_zone_id=existing_rule.get(
                            "validity_time_zone_id", ""
                        ),
                        enforce_time_validity=existing_rule.get(
                            "enforce_time_validity", ""
                        ),
                        user_agent_types=existing_rule.get("user_agent_types", ""),
                        user_risk_score_levels=existing_rule.get(
                            "user_risk_score_levels", ""
                        ),
                        device_trust_levels=existing_rule.get(
                            "device_trust_levels", ""
                        ),
                        cbi_profile=existing_rule.get("cbi_profile", ""),
                    )
                )

                module.warn("Payload Update for SDK: {}".format(update_rule))
                updated_rule = client.cloudappcontrol.update_rule(
                    rule_type, **update_rule
                ).to_dict()
                module.exit_json(changed=True, data=updated_rule)
        else:
            module.warn("Creating new rule as no existing rule found")
            """Create"""
            create_rule = deleteNone(
                dict(
                    name=rule.get("name", ""),
                    description=rule.get("description", ""),
                    enabled=rule.get("enabled", ""),
                    actions=rule.get("actions", ""),
                    type=rule.get("type", ""),
                    order=rule.get("order", ""),
                    locations=rule.get("locations", ""),
                    groups=rule.get("groups", ""),
                    departments=rule.get("departments", ""),
                    users=rule.get("users", ""),
                    device_groups=rule.get("device_groups", ""),
                    devices=rule.get("devices", ""),
                    time_windows=rule.get("time_windows", ""),
                    rank=rule.get("rank", ""),
                    applications=rule.get("applications", ""),
                    tenancy_profile_ids=rule.get("tenancy_profile_ids", ""),
                    cloud_app_risk_profile=rule.get("cloud_app_risk_profile", ""),
                    cloud_app_instances=rule.get("cloud_app_instances", ""),
                    cascading_enabled=rule.get("cascading_enabled", ""),
                    time_quota=rule.get("time_quota", ""),
                    size_quota=rule.get("size_quota", ""),
                    location_groups=rule.get("location_groups", ""),
                    labels=rule.get("labels", ""),
                    validity_start_time=rule.get("validity_start_time", ""),
                    validity_end_time=rule.get("validity_end_time", ""),
                    validity_time_zone_id=rule.get("validity_time_zone_id", ""),
                    enforce_time_validity=rule.get("enforce_time_validity", ""),
                    user_agent_types=rule.get("user_agent_types", ""),
                    user_risk_score_levels=rule.get("user_risk_score_levels", ""),
                    device_trust_levels=rule.get("device_trust_levels", ""),
                    cbi_profile=rule.get("cbi_profile", ""),
                )
            )
            module.warn("Payload for SDK: {}".format(create_rule))
            new_rule = client.cloudappcontrol.add_rule(
                rule_type, **create_rule
            ).to_dict()
            module.exit_json(changed=True, data=new_rule)
    elif (
        state == "absent"
        and existing_rule is not None
        and existing_rule.get("id") is not None
    ):
        # Delete the rule with the correct rule_type
        code = client.cloudappcontrol.delete_rule(
            rule_type, rule_id=existing_rule.get("id")
        )
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
    id_name_url_dict_spec = dict(
        id=dict(type="str", required=True),
        name=dict(type="str", required=True),
        url=dict(type="str", required=True),
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        enabled=dict(type="bool", required=False),
        order=dict(type="int", required=False),
        actions=dict(type="list", elements="str", required=False),
        rank=dict(type="int", required=False, default=7),
        locations=id_spec,
        groups=id_spec,
        departments=id_spec,
        device_groups=id_spec,
        devices=id_spec,
        users=id_spec,
        time_windows=id_spec,
        location_groups=id_spec,
        labels=id_spec,
        tenancy_profile_ids=id_spec,
        cloud_app_risk_profile=id_spec,
        cloud_app_instances=id_spec,
        time_quota=dict(type="int", required=False),
        size_quota=dict(type="int", required=False),
        validity_start_time=dict(type="str", required=False),
        validity_end_time=dict(type="str", required=False),
        validity_time_zone_id=dict(type="str", required=False),
        enforce_time_validity=dict(type="bool", required=False),
        applications=dict(type="list", elements="str", required=False),
        cascading_enabled=dict(type="bool", required=False),
        cbi_profile=dict(
            type="dict",
            options=id_name_url_dict_spec,
            required=False,
        ),
        user_agent_types=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "OPERA",
                "FIREFOX",
                "MSIE",
                "MSEDGE",
                "CHROME",
                "SAFARI",
                "OTHER",
                "MSCHREDGE",
            ],
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
        user_risk_score_levels=dict(
            type="list",
            elements="str",
            required=False,
            choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        ),
        rule_type=dict(  # This is mapped to `type` in the payload
            type="str",
            required=True,
            choices=[
                "SOCIAL_NETWORKING",
                "STREAMING_MEDIA",
                "WEBMAIL",
                "INSTANT_MESSAGING",
                "BUSINESS_PRODUCTIVITY",
                "ENTERPRISE_COLLABORATION",
                "SALES_AND_MARKETING",
                "SYSTEM_AND_DEVELOPMENT",
                "CONSUMER",
                "HOSTING_PROVIDER",
                "IT_SERVICES",
                "FILE_SHARE",
                "DNS_OVER_HTTPS",
                "HUMAN_RESOURCES",
                "LEGAL",
                "HEALTH_CARE",
                "FINANCE",
                "CUSTOM_CAPP",
                "AI_ML",
            ],
        ),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    if not HAS_PYTZ:
        module.fail_json(
            msg="The 'pytz' library is required by this module.",
            exception=PYTZ_IMPORT_ERROR,
        )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
