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
module: zia_url_filtering_rules
short_description: "Adds a new URL Filtering rule."
description: "Adds a new URL Filtering rule."
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
  enabled:
    description:
        - Determines whether the URL Filtering rule is enabled or disabled
    required: false
    type: bool
  order:
    description: "Rule order number of the URL Filtering policy rule"
    required: true
    type: int
  action:
    description:
      - Action taken when traffic matches rule criteria
      - When the action is set to CAUTION the attribute request_methods accepts only the following values are CONNECT GET HEAD
    required: true
    type: str
    choices:
        - ANY
        - BLOCK
        - CAUTION
        - ALLOW
        - ISOLATE
        - ICAP_RESPONSE
  protocols:
    description:
        - Protocol criteria
    required: true
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
  workload_groups:
    description: "The list of preconfigured workload groups to which the policy must be applied."
    type: list
    elements: int
    required: false
  url_categories:
    description:
      - The URL categories to which the rule applies
      - Use the info resource zia_url_categories_info to retrieve the category names.
    required: false
    type: list
    elements: str
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
        - PROPFIND
        - PROPPATCH
        - MOVE
        - MKCOL
        - LOCK
        - COPY
        - UNLOCK
        - PATCH
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
    elements: int
    required: false
  override_groups:
    description:
        - Name-ID pairs of groups for which this rule can be overridden.
        - Applicable only if block_override is set to true and action is BLOCK.
        - If this override_groups is not set, BLOCK action can be overridden for any group.
    type: list
    elements: int
    required: false
  block_override:
    description:
        - When set to true, a BLOCK action triggered by the rule could be overridden.
        - If true and both override_group and override_users are not set, the BLOCK triggered by this rule could be overridden for any users.
        - If block_override is not set, BLOCK action cannot be overridden.
    type: bool
    required: false
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
    elements: int
    required: false
  labels:
    description:
        - The URL Filtering rule label. Rule labels allow you to logically group your organization policy rules.
        - Policy rules that are not associated with a rule label are grouped under the Untagged label.
    type: list
    elements: int
    required: false
  source_ip_groups:
    description:
        - User-defined source IP address groups for which the rule is applicable.
        - If not set, the rule is not restricted to a specific source IP address group.
    type: list
    elements: int
    required: false
  enforce_time_validity:
    description:
        - Enforce a set a validity time period for the URL Filtering rule.
    type: bool
  validity_start_time:
    description:
      - If enforce_time_validity is set to true, the URL Filtering rule will be valid starting on this date and time.
      - Example ( 11/20/2023 11:59 PM )
      - Notice that validity_start_time cannot be in the past
    required: false
    type: str
  validity_time_zone_id:
    description:
      - If enforceTimeValidity is set to true, the URL Filtering rule date and time is valid based on this time zone ID.
    required: false
    type: str
  validity_end_time:
    description:
      - If enforce_time_validity is set to true, the URL Filtering rule will cease to be valid on this end date and time.
      - Example ( 12/21/2023 12:00 AM )
    required: false
    type: str
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
    provider: '{{ provider }}'
    name: "URL_Ansible_Example"
    description: "URL_Ansible_Example"
    enabled: "ENABLED"
    action: "ALLOW"
    order: 1
    source_ip_groups:
      - 4361664
      - 4522587
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
    PYTZ_IMPORT_ERROR = None
except ImportError:
    pytz = None
    HAS_PYTZ = False
    PYTZ_IMPORT_ERROR = missing_required_lib("pytz")


def validate_and_convert_time_fields(rule):
    if not HAS_PYTZ:
        raise ImportError(PYTZ_IMPORT_ERROR)

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


def normalize_rule(rule):
    if not rule:
        return {}

    normalized = rule.copy()
    computed_values = ["profile_seq"]
    for attr in computed_values:
        if (
            "cbi_profile" in normalized
            and isinstance(normalized["cbi_profile"], dict)
            and attr in normalized["cbi_profile"]
        ):
            normalized["cbi_profile"].pop(attr, None)

    return normalized


def preprocess_rule(rule, params):
    for attr in params:
        if attr in rule and rule[attr] is not None:
            if isinstance(rule[attr], list):
                if all(isinstance(item, dict) and "id" in item for item in rule[attr]):
                    rule[attr] = [item["id"] for item in rule[attr]]
                else:
                    rule[attr] = sorted(rule[attr])
    return rule


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)

    params = [
        "id",
        "name",
        "description",
        "enabled",
        "order",
        "rank",
        "action",
        "protocols",
        "request_methods",
        "locations",
        "groups",
        "departments",
        "users",
        "override_users",
        "override_groups",
        "block_override",
        "url_categories",
        "time_quota",
        "size_quota",
        "time_windows",
        "location_groups",
        "labels",
        "user_agent_types",
        "device_trust_levels",
        "device_groups",
        "devices",
        "user_risk_score_levels",
        "validity_start_time",
        "validity_end_time",
        "validity_time_zone_id",
        "enforce_time_validity",
        "end_user_notification_url",
        "cipa_rule",
        "cbi_profile",
        "workload_groups",
        "source_ip_groups",
    ]

    # Only include attributes that are explicitly set in the playbook
    rule = {}
    for param in params:
        if module.params.get(param) is not None:
            rule[param] = module.params.get(param)

    module.debug(f"Initial parameters received (only explicitly set values): {rule}")

    # Normalize boolean attributes (only if they exist in the rule)
    bool_attributes = ["enforce_time_validity", "block_override"]
    rule = normalize_boolean_attributes(rule, bool_attributes)
    module.debug(f"Parameters after boolean normalization: {rule}")

    # Validate and convert fields (only if enforce_time_validity is set)
    if "enforce_time_validity" in rule:
        validate_and_convert_time_fields(rule)
        module.debug(f"Parameters after time field validation/conversion: {rule}")
    else:
        module.debug("Skipping time validation as enforce_time_validity is not set")

    rule_id = rule.get("id")
    rule_name = rule.get("name")

    existing_rule = None
    if rule_id is not None:
        module.debug(f"Fetching existing rule with ID: {rule_id}")
        result, _unused, error = client.url_filtering.get_rule(rule_id=rule_id)
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
        result, _unused, error = client.url_filtering.list_rules()
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

    for k in ["protocols", "request_methods", "user_agent_types"]:
        if k in desired_rule and isinstance(desired_rule[k], list):
            desired_rule[k] = sorted(desired_rule[k])

    current_rule = normalize_rule(existing_rule) if existing_rule else {}

    for k in ["protocols", "request_methods", "user_agent_types"]:
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
        "protocols",
        "request_methods",
        "locations",
        "groups",
        "departments",
        "users",
        "override_users",
        "override_groups",
        "url_categories",
        "time_windows",
        "location_groups",
        "labels",
        "user_agent_types",
        "device_trust_levels",
        "device_groups",
        "devices",
        "user_risk_score_levels",
        "workload_groups",
        "source_ip_groups",
    ]

    # Attributes where order should be ignored
    order_agnostic_attributes = ["protocols", "user_agent_types", "request_methods"]

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

        # Special handling for quota fields - treat 0 and None as equivalent
        if key in ["time_quota", "size_quota"]:
            if desired_value in (None, 0) and current_value in (None, 0):
                continue
            if desired_value is None:
                desired_value = 0
            if current_value is None:
                current_value = 0

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
                    # module.warn(
                    #     f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
                    # )
        elif current_value != desired_value:
            differences_detected = True
            # module.warn(
            #     f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
            # )

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
                        "rule_id": rule_id_to_update,
                        "name": desired_rule.get("name"),
                        "description": desired_rule.get("description"),
                        "enabled": desired_rule.get("enabled"),
                        "order": desired_rule.get("order"),
                        "rank": desired_rule.get("rank"),
                        "action": desired_rule.get("action"),
                        "protocols": desired_rule.get("protocols"),
                        "request_methods": desired_rule.get("request_methods"),
                        "locations": desired_rule.get("locations"),
                        "groups": desired_rule.get("groups"),
                        "departments": desired_rule.get("departments"),
                        "users": desired_rule.get("users"),
                        "override_users": desired_rule.get("override_users"),
                        "override_groups": desired_rule.get("override_groups"),
                        "url_categories": desired_rule.get("url_categories"),
                        "time_quota": desired_rule.get("time_quota"),
                        "size_quota": desired_rule.get("size_quota"),
                        "time_windows": desired_rule.get("time_windows"),
                        "location_groups": desired_rule.get("location_groups"),
                        "labels": desired_rule.get("labels"),
                        "user_agent_types": desired_rule.get("user_agent_types"),
                        "device_trust_levels": desired_rule.get("device_trust_levels"),
                        "device_groups": desired_rule.get("device_groups"),
                        "devices": desired_rule.get("devices"),
                        "user_risk_score_levels": desired_rule.get(
                            "user_risk_score_levels"
                        ),
                        "validity_start_time": desired_rule.get("validity_start_time"),
                        "validity_end_time": desired_rule.get("validity_end_time"),
                        "validity_time_zone_id": desired_rule.get(
                            "validity_time_zone_id"
                        ),
                        "end_user_notification_url": desired_rule.get(
                            "end_user_notification_url"
                        ),
                        "cipa_rule": desired_rule.get("cipa_rule"),
                        "cbi_profile": desired_rule.get("cbi_profile"),
                        "workload_groups": desired_rule.get("workload_groups"),
                        "source_ip_groups": desired_rule.get("source_ip_groups"),
                    }
                )

                # Conditionally add the special boolean fields if they were set
                if "block_override" in desired_rule:
                    update_data["block_override"] = desired_rule["block_override"]
                if "enforce_time_validity" in desired_rule:
                    update_data["enforce_time_validity"] = desired_rule[
                        "enforce_time_validity"
                    ]

                module.warn("Payload Update for SDK: {}".format(update_data))
                updated_rule, _unused, error = client.url_filtering.update_rule(
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
                    "enabled": desired_rule.get("enabled"),
                    "order": desired_rule.get("order"),
                    "rank": desired_rule.get("rank"),
                    "action": desired_rule.get("action"),
                    "protocols": desired_rule.get("protocols"),
                    "request_methods": desired_rule.get("request_methods"),
                    "locations": desired_rule.get("locations"),
                    "groups": desired_rule.get("groups"),
                    "departments": desired_rule.get("departments"),
                    "users": desired_rule.get("users"),
                    "override_users": desired_rule.get("override_users"),
                    "override_groups": desired_rule.get("override_groups"),
                    "url_categories": desired_rule.get("url_categories"),
                    "time_quota": desired_rule.get("time_quota"),
                    "size_quota": desired_rule.get("size_quota"),
                    "time_windows": desired_rule.get("time_windows"),
                    "location_groups": desired_rule.get("location_groups"),
                    "labels": desired_rule.get("labels"),
                    "user_agent_types": desired_rule.get("user_agent_types"),
                    "device_trust_levels": desired_rule.get("device_trust_levels"),
                    "device_groups": desired_rule.get("device_groups"),
                    "devices": desired_rule.get("devices"),
                    "user_risk_score_levels": desired_rule.get(
                        "user_risk_score_levels"
                    ),
                    "validity_start_time": desired_rule.get("validity_start_time"),
                    "validity_end_time": desired_rule.get("validity_end_time"),
                    "validity_time_zone_id": desired_rule.get("validity_time_zone_id"),
                    "end_user_notification_url": desired_rule.get(
                        "end_user_notification_url"
                    ),
                    "cipa_rule": desired_rule.get("cipa_rule"),
                    "cbi_profile": desired_rule.get("cbi_profile"),
                    "workload_groups": desired_rule.get("workload_groups"),
                    "source_ip_groups": desired_rule.get("source_ip_groups"),
                }
            )

            # Conditionally add the special boolean fields if they were set
            if "block_override" in desired_rule:
                create_data["block_override"] = desired_rule["block_override"]
            if "enforce_time_validity" in desired_rule:
                create_data["enforce_time_validity"] = desired_rule[
                    "enforce_time_validity"
                ]

            module.warn("Payload for SDK: {}".format(create_data))
            new_rule, _unused, error = client.url_filtering.add_rule(**create_data)
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
            _unused, _unused, error = client.url_filtering.delete_rule(
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
        order=dict(type="int", required=True),
        rank=dict(type="int", required=False, default=7),
        action=dict(
            type="str",
            required=True,
            choices=["ANY", "BLOCK", "CAUTION", "ALLOW", "ISOLATE", "ICAP_RESPONSE"],
        ),
        protocols=dict(
            type="list",
            elements="str",
            required=True,
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
        request_methods=dict(
            type="list",
            elements="str",
            required=False,
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
                "PROPFIND",
                "PROPPATCH",
                "MOVE",
                "MKCOL",
                "LOCK",
                "COPY",
                "UNLOCK",
                "PATCH",
            ],
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
        locations=id_spec,
        groups=id_spec,
        departments=id_spec,
        users=id_spec,
        override_users=id_spec,
        override_groups=id_spec,
        source_ip_groups=id_spec,
        block_override=dict(type="bool", required=False),
        url_categories=dict(type="list", elements="str", required=False),
        time_quota=dict(type="int", required=False),
        size_quota=dict(type="int", required=False),
        time_windows=id_spec,
        location_groups=id_spec,
        labels=id_spec,
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
        device_groups=id_spec,
        devices=id_spec,
        validity_start_time=dict(type="str", required=False),
        validity_end_time=dict(type="str", required=False),
        validity_time_zone_id=dict(type="str", required=False),
        enforce_time_validity=dict(type="bool", required=False),
        end_user_notification_url=dict(type="str", required=False),
        cipa_rule=dict(type="bool", required=False),
        workload_groups=id_spec,
        cbi_profile=dict(
            type="dict",
            options=id_name_url_dict_spec,
            required=False,
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
