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
module: zia_url_filtering_rules
short_description: "Adds a new URL Filtering rule."
description: "Adds a new URL Filtering rule."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.credentials_set
  - zscaler.ziacloud.fragments.state
options:
  id:
    description: "Unique identifier for the URL Filtering policy rule"
    required: false
    type: int
  name:
    description: "Name of the URL Filtering policy rule"
    required: true
    type: str
  description:
    description: "Additional information about the rule"
    required: false
    type: str
  order:
    description: "Rule order number of the URL Filtering policy rule"
    required: true
    type: int
  protocols:
    description:
        - Protocol criteria
    required: false
    type: str
    choices:
        - SMRULEF_ZPA_BROKERS_RULE
        - ANY_RULE
        - TCP_RULE
        - UDP_RULE
        - DOHTTPS_RULE
        - TUNNELSSL_RULE
        - HTTP_PROXY
        - FOHTTP_RULE
        - FTP_RULE
        - HTTPS_RULE
        - HTTP_RULE
        - SSL_RULE
        - TUNNEL_RULE
        - WEBSOCKETSSL_RULE
        - WEBSOCKET_RULE
  locations:
    description:
        - Name-ID pairs of locations for which rule must be applied
    type: list
    elements: str
    required: false
  groups:
    description:
        - Name-ID pairs of groups for which rule must be applied
    type: list
    elements: str
    required: false
  departments:
    description:
        - Name-ID pairs of departments for which rule will be applied
    type: list
    elements: str
    required: false
  users:
    description:
        - Name-ID pairs of users for which rule must be applied
    type: list
    elements: str
    required: false
  workload_groups:
    description: "The list of preconfigured workload groups to which the policy must be applied."
    type: list
    elements: int
    required: false
  url_categories:
    description:
        - List of URL categories for which rule must be applied
    type: list
    elements: str
    required: false
  enabled:
    description:
        - Determines whether the URL Filtering rule is enabled or disabled
    required: false
    type: str
    choices:
        - DISABLED
        - ENABLED
    default: ENABLED
  time_windows:
    description:
        - Name-ID pairs of time interval during which rule must be enforced.
    type: list
    elements: str
    required: false
  rank:
    description:
        - Admin rank of the admin who creates this rule
    required: false
    default: 7
    type: int
  request_methods:
    description:
        - Request method for which the rule must be applied.
        - If not set, rule will be applied to all methods"
    type: list
    elements: str
    required: false
    choices:
        - OPTIONS
        - GET
        - HEAD
        - POST
        - PUT
        - DELETE
        - TRACE
        - CONNECT
        - OTHER
  end_user_notification_url:
    description:
      - URL of end user notification page to be displayed when the rule is matched.
      - Not applicable if either override_users or override_groups is specified.
    required: false
    type: str
  override_users:
    description:
        - Name-ID pairs of users for which this rule can be overridden.
        - Applicable only if block_override is set to true, action is BLOCK and override_groups is not set.
        - If this override_users is not set, BLOCK action can be overridden for any user.
    type: list
    elements: str
    required: false
  override_groups:
    description:
        - Name-ID pairs of groups for which this rule can be overridden.
        - Applicable only if block_override is set to true and action is BLOCK.
        - If this override_groups is not set, BLOCK action can be overridden for any group.
    type: list
    elements: str
    required: false
  block_override:
    description:
        - When set to true, a BLOCK action triggered by the rule could be overridden.
        - If true and both override_group and override_users are not set, the BLOCK triggered by this rule could be overridden for any users.
        - If block_override is not set, BLOCK action cannot be overridden.
    type: bool
    required: false
    default: false
  time_quota:
    description:
        - Action must be set to CAUTION
        - Time quota in minutes, after which the URL Filtering rule is applied.
        - The allowed range is between 15 minutes and 600 minutes.
        - If not set, no quota is enforced. If a policy rule action is set to BLOCK, this field is not applicable.
    required: false
    type: int
  size_quota:
    description:
        - Action must be set to CAUTION
        - Size quota in MB beyond which the URL Filtering rule is applied.
        - The allowed range is between 10 MB and 100000 MB
        - If not set, no quota is enforced. If a policy rule action is set to BLOCK, this field is not applicable.
    required: false
    type: int
  location_groups:
    description:
        - Name-ID pairs of the location groups to which the rule must be applied.
    type: list
    elements: str
    required: false
  labels:
    description:
        - The URL Filtering rule label. Rule labels allow you to logically group your organization policy rules.
        - Policy rules that are not associated with a rule label are grouped under the Untagged label.
    type: list
    elements: str
    required: false
  enforce_time_validity:
    description:
        - Enforce a set a validity time period for the URL Filtering rule.
    type: bool
    default: false
  validity_start_time:
    description:
      - If enforce_time_validity is set to true, the URL Filtering rule will be valid starting on this date and time.
      - Example ( 11/20/2023 11:59 PM )
      - Notice that validity_start_time cannot be in the past
    required: false
    type: str
  validity_end_time:
    description:
      - If enforce_time_validity is set to true, the URL Filtering rule will cease to be valid on this end date and time.
      - Example ( 12/21/2023 12:00 AM )
    required: false
    type: str
  action:
    description:
      - Action taken when traffic matches rule criteria
      - When the action is set to CAUTION the attribute request_methods accepts only the following values are CONNECT GET HEAD
    required: false
    type: str
    choices:
        - ANY
        - NONE
        - BLOCK
        - CAUTION
        - ALLOW
        - ICAP_RESPONSE
  cipa_rule:
    description:
        - If set to true, the CIPA Compliance rule is enabled
    type: bool
  cbi_profile:
      description:
        - The cloud browser isolation profile to which the ISOLATE action is applied in the URL Filtering Policy rules.
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
- name: Create/Update/Delete a URL Filtering Rule.
  zscaler.ziacloud.zia_url_filtering_rules:
    name: "URL_Ansible_Example"
    description: "URL_Ansible_Example"
    enabled: "ENABLED"
    action: "ALLOW"
    order: 1
    protocols:
        - "HTTPS_RULE"
        - "HTTP_RULE"
    request_methods:
        - "CONNECT"
        - "DELETE"
        - "GET"
        - "HEAD"
        - "OPTIONS"
        - "OTHER"
        - "POST"
        - "PUT"
        - "TRACE"
"""

RETURN = r"""
# The newly created URL Filtering Rule resource record.
"""

import time
import pytz
from datetime import datetime
from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def validate_and_convert_time_fields(rule):
    """
    Validate time-related fields and convert start and end times to epoch if enforce_time_validity is True.
    """
    enforce_time_validity = rule.get("enforce_time_validity")
    if enforce_time_validity:
        # Mandatory fields check
        for field in [
            "validity_start_time",
            "validity_end_time",
            "validity_time_zone_id",
        ]:
            if not rule.get(field):
                raise ValueError(
                    f"'{field}' must be set when 'enforce_time_validity' is True"
                )

        # Validate and convert time zone
        timezone_id = rule["validity_time_zone_id"]
        if timezone_id not in pytz.all_timezones:
            raise ValueError(f"Invalid timezone ID: {timezone_id}")

        # Convert start and end times to epoch
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
    # Adjust for action 'CAUTION'
    if rule.get("action") == "CAUTION":
        # Set request methods when action is 'CAUTION'
        rule["request_methods"] = ["CONNECT", "GET", "HEAD"]

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
    normalized = rule.copy()

    # Add 'profile_seq' to the list of computed values to be removed
    computed_values = ["profile_seq"]
    for attr in computed_values:
        if "cbi_profile" in normalized and attr in normalized["cbi_profile"]:
            normalized["cbi_profile"].pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    rule = dict()
    params = [
        "id",
        "name",
        "order",
        "protocols",
        "locations",
        "groups",
        "departments",
        "users",
        "url_categories",
        "enabled",
        "time_windows",
        "rank",
        "request_methods",
        "end_user_notification_url",
        "override_users",
        "override_groups",
        "block_override",
        "time_quota",
        "size_quota",
        "description",
        "location_groups",
        "labels",
        "validity_start_time",
        "validity_end_time",
        "validity_time_zone_id",
        "enforce_time_validity",
        "action",
        "ciparule",
        "user_agent_types",
        "device_trust_levels",
        "device_groups",
        "devices",
        "user_risk_score_levels",
        "cbi_profile",
        "workload_groups"
    ]
    for param_name in params:
        rule[param_name] = module.params.get(param_name, None)

    # Add the validation and conversion logic here
    validate_and_convert_time_fields(rule)

    # Validate and convert additional fields
    validate_additional_fields(rule)

    rule_id = rule.get("id", None)
    rule_name = rule.get("name", None)

    existing_rule = None
    if rule_id is not None:
        ruleBox = client.url_filtering.get_rule(rule_id=rule_id)
        if ruleBox is not None:
            existing_rule = ruleBox.to_dict()
    elif rule_name is not None:
        rules = client.url_filtering.list_rules().to_list()
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

        # Handle 'block_override' and 'enforce_time_validity' specifically
        if key in ["block_override", "enforce_time_validity"]:
            if desired_value is None:
                if current_value is False:  # Assuming 'False' is the default value
                    continue  # Skip as it's the default value
            elif desired_value == current_value:
                continue  # Skip as values are the same

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
                        protocols=existing_rule.get("protocols"),
                        locations=existing_rule.get("locations"),
                        groups=existing_rule.get("groups"),
                        departments=existing_rule.get("departments"),
                        users=existing_rule.get("users"),
                        device_groups=existing_rule.get("device_groups"),
                        devices=existing_rule.get("devices"),
                        url_categories=existing_rule.get("url_categories"),
                        enabled=existing_rule.get("enabled"),
                        time_windows=existing_rule.get("time_windows"),
                        rank=existing_rule.get("rank"),
                        request_methods=existing_rule.get("request_methods"),
                        end_user_notification_url=existing_rule.get(
                            "end_user_notification_url"
                        ),
                        override_users=existing_rule.get("override_users"),
                        override_groups=existing_rule.get("override_groups"),
                        block_override=existing_rule.get("block_override"),
                        time_quota=existing_rule.get("time_quota"),
                        size_quota=existing_rule.get("size_quota"),
                        description=existing_rule.get("description"),
                        location_groups=existing_rule.get("location_groups"),
                        labels=existing_rule.get("labels"),
                        validity_start_time=existing_rule.get("validity_start_time"),
                        validity_end_time=existing_rule.get("validity_end_time"),
                        validity_time_zone_id=existing_rule.get(
                            "validity_time_zone_id"
                        ),
                        enforce_time_validity=existing_rule.get(
                            "enforce_time_validity"
                        ),
                        action=existing_rule.get("action"),
                        cipa_rule=existing_rule.get("cipa_rule"),
                        user_agent_types=existing_rule.get("user_agent_types"),
                        user_risk_score_levels=existing_rule.get(
                            "user_risk_score_levels"
                        ),
                        device_trust_levels=existing_rule.get("device_trust_levels"),
                        cbi_profile=existing_rule.get("cbi_profile"),
                        workload_groups=existing_rule.get("workload_groups"),
                    )
                )

                module.warn("Payload Update for SDK: {}".format(update_rule))
                updated_rule = client.url_filtering.update_rule(**update_rule).to_dict()
                module.exit_json(changed=True, data=updated_rule)
        else:
            module.warn("Creating new rule as no existing rule found")
            """Create"""
            create_rule = deleteNone(
                dict(
                    name=rule.get("name"),
                    order=rule.get("order"),
                    protocols=rule.get("protocols"),
                    locations=rule.get("locations"),
                    groups=rule.get("groups"),
                    departments=rule.get("departments"),
                    users=rule.get("users"),
                    device_groups=rule.get("device_groups"),
                    devices=rule.get("devices"),
                    url_categories=rule.get("url_categories"),
                    enabled=rule.get("enabled"),
                    time_windows=rule.get("time_windows"),
                    rank=rule.get("rank"),
                    request_methods=rule.get("request_methods"),
                    end_user_notification_url=rule.get("end_user_notification_url"),
                    override_users=rule.get("override_users"),
                    override_groups=rule.get("override_groups"),
                    block_override=rule.get("block_override"),
                    time_quota=rule.get("time_quota"),
                    size_quota=rule.get("size_quota"),
                    description=rule.get("description"),
                    location_groups=rule.get("location_groups"),
                    labels=rule.get("labels"),
                    validity_start_time=rule.get("validity_start_time"),
                    validity_end_time=rule.get("validity_end_time"),
                    validity_time_zone_id=rule.get("validity_time_zone_id"),
                    enforce_time_validity=rule.get("enforce_time_validity"),
                    action=rule.get("action"),
                    cipa_rule=rule.get("cipa_rule"),
                    user_agent_types=rule.get("user_agent_types"),
                    user_risk_score_levels=rule.get("user_risk_score_levels"),
                    device_trust_levels=rule.get("device_trust_levels"),
                    cbi_profile=rule.get("cbi_profile"),
                    workload_groups=rule.get("workload_groups"),
                )
            )
            module.warn("Payload for SDK: {}".format(create_rule))
            new_rule = client.url_filtering.add_rule(**create_rule).to_dict()
            module.exit_json(changed=True, data=new_rule)
    elif (
        state == "absent"
        and existing_rule is not None
        and existing_rule.get("id") is not None
    ):
        code = client.url_filtering.delete_rule(rule_id=existing_rule.get("id"))
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
        id=dict(type="str", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        enabled=dict(type="bool", required=False),
        order=dict(type="int", required=True),
        rank=dict(type="int", required=False, default=7),
        locations=id_spec,
        groups=id_spec,
        departments=id_spec,
        device_groups=id_spec,
        devices=id_spec,
        users=id_spec,
        override_users=id_spec,
        override_groups=id_spec,
        time_windows=id_spec,
        location_groups=id_spec,
        labels=id_spec,
        workload_groups=id_spec,
        end_user_notification_url=dict(type="str", required=False),
        block_override=dict(type="bool", required=False),
        time_quota=dict(type="int", required=False),
        size_quota=dict(type="int", required=False),
        validity_start_time=dict(type="str", required=False),
        validity_end_time=dict(type="str", required=False),
        validity_time_zone_id=dict(type="str", required=False),
        enforce_time_validity=dict(type="bool", required=False),
        url_categories=dict(type="list", elements="str", required=False),
        cipa_rule=dict(type="bool", required=False),
        cbi_profile=dict(
            type="dict",
            options=id_name_url_dict_spec,
            required=True,
        ),
        action=dict(
            type="str",
            required=False,
            choices=["BLOCK", "CAUTION", "ALLOW", "ISOLATE", "ICAP_RESPONSE"],
        ),
        protocols=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "SMRULEF_ZPA_BROKERS_RULE",
                "ANY_RULE",
                "TCP_RULE",
                "UDP_RULE",
                "DOHTTPS_RULE",
                "TUNNELSSL_RULE",
                "HTTP_PROXY",
                "FOHTTP_RULE",
                "FTP_RULE",
                "HTTPS_RULE",
                "HTTP_RULE",
                "SSL_RULE",
                "TUNNEL_RULE",
                "WEBSOCKETSSL_RULE",
                "WEBSOCKET_RULE",
            ],
        ),
        request_methods=dict(
            type="list",
            elements="str",
            required=True,
            choices=[
                "OPTIONS",
                "GET",
                "HEAD",
                "POST",
                "PUT",
                "DELETE",
                "TRACE",
                "CONNECT",
                "OTHER",
            ],
        ),
        user_agent_types=dict(
            type="list",
            elements="str",
            required=True,
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
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
