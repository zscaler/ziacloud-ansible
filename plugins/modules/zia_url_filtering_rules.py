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
options:
  username:
    description: "Username of admin user that is provisioned"
    required: true
    type: str
  password:
    description: "Password of the admin user"
    required: true
    type: str
  api_key:
    description: "The obfuscated form of the API key"
    required: true
    type: str
  base_url:
    description: "The host and basePath for the cloud services API"
    required: true
    type: str
  id:
    description: "URL Filtering Rule ID"
    required: false
    type: int
  name:
    description: "Name of the URL Filtering rule"
    required: true
    type: str
  order:
    description: "Order of execution of rule with respect to other URL Filtering rules"
    required: true
    type: int
  protocols:
    description: "Protocol criteria"
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
  locations:
    description: "Name-ID pairs of locations for which rule must be applied"
    type: list
    elements: str
    required: false
  groups:
    description: "Name-ID pairs of groups for which rule must be applied"
    type: list
    elements: str
    required: false
  departments:
    description: "Name-ID pairs of departments for which rule will be applied"
    type: list
    elements: str
    required: false
  users:
    description: "Name-ID pairs of users for which rule must be applied"
    type: list
    elements: str
    required: false
  url_categories:
    description: "List of URL categories for which rule must be applied"
    type: list
    elements: str
    required: false
  rule_state:
    description:
        - Determines whether the URL Filtering rule is enabled or disabled
    required: false
    type: str
    choices:
        - DISABLED
        - ENABLED
    default: ENABLED
  time_windows:
    description: "Name-ID pairs of time interval during which rule must be enforced."
    type: list
    elements: str
    required: false
  rank:
    description: "Admin rank of the admin who creates this rule"
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
      - Not applicable if either 'overrideUsers' or 'overrideGroups' is specified.
    required: false
    type: str
  override_users:
    description:
        - Name-ID pairs of users for which this rule can be overridden.
        - Applicable only if blockOverride is set to 'true', action is 'BLOCK' and overrideGroups is not set.
        - If this overrideUsers is not set, 'BLOCK' action can be overridden for any user.
    type: list
    elements: str
    required: false
  override_groups:
    description:
        - Name-ID pairs of groups for which this rule can be overridden.
        - Applicable only if blockOverride is set to 'true' and action is 'BLOCK'.
        - If this overrideGroups is not set, 'BLOCK' action can be overridden for any group.
    type: list
    elements: str
    required: false
  block_override:
    description:
        - When set to true, a 'BLOCK' action triggered by the rule could be overridden.
        - If true and both overrideGroup and overrideUsers are not set, the BLOCK triggered by this rule could be overridden for any users.
        - If blockOverride is not set, 'BLOCK' action cannot be overridden.
    type: bool
    required: false
    default: false
  time_quota:
    description:
        - Time quota in minutes, after which the URL Filtering rule is applied.
        - If not set, no quota is enforced. If a policy rule action is set to 'BLOCK', this field is not applicable.
    required: false
    type: int
  size_quota:
    description:
        - Size quota in KB beyond which the URL Filtering rule is applied.
        - If not set, no quota is enforced. If a policy rule action is set to 'BLOCK', this field is not applicable.
    required: false
    type: int
  description:
    description: "Additional information about the URL Filtering rule"
    required: false
    type: str
  location_groups:
    description: "Name-ID pairs of the location groups to which the rule must be applied."
    type: list
    elements: str
    required: false
  labels:
    description:
        - The URL Filtering rule's label. Rule labels allow you to logically group your organization's policy rules.
        - Policy rules that are not associated with a rule label are grouped under the Untagged label.
    type: list
    elements: str
    required: false
  validity_start_time:
    description: "If enforceTimeValidity is set to true, the URL Filtering rule will be valid starting on this date and time."
    required: false
    type: int
  validity_end_time:
    description: "If enforceTimeValidity is set to true, the URL Filtering rule will cease to be valid on this end date and time."
    required: false
    type: int
  validity_time_zone_id:
    description: "If enforceTimeValidity is set to true, the URL Filtering rule date and time will be valid based on this time zone ID."
    required: false
    type: int
  last_modified_time:
    description: "If enforceTimeValidity is set to true, the URL Filtering rule date and time will be valid based on this time zone ID."
    required: false
    type: int
  last_modified_by:
    description: "Who modified the rule last"
    type: list
    elements: str
    required: false
  enforce_time_validity:
    description: "Enforce a set a validity time period for the URL Filtering rule."
    type: bool
    default: false
  action:
    description: "Action taken when traffic matches rule criteria"
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
    description: "If set to true, the CIPA Compliance rule is enabled"
    type: bool
    default: false

"""

EXAMPLES = """
- name: Create/Update/Delete a URL Filtering Rule.
  zscaler.ziacloud.zia_url_filtering_rules:
    name: "URL_Ansible_Example"
    description: "URL_Ansible_Example"
    rule_state: "ENABLED"
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

RETURN = """
# The newly created URL Filtering Rule resource record.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    deleteNone,
    zia_argument_spec,
)
from numpy import delete
from zscaler import ZIA


def core(module):
    state = module.params.get("state", None)
    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )
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
        "state",
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
        "last_modified_time",
        "last_modified_by",
        "enforce_time_validity",
        "action",
        "ciparule",
    ]
    for param_name in params:
        rule[param_name] = module.params.get(param_name, None)
    rule_id = rule.get("id", None)
    rule_name = rule.get("name", None)
    existing_rule = None
    if rule_id is not None:
        ruleBox = client.url_filters.get_rule(rule_id=rule_id)
        if ruleBox is not None:
            existing_rule = ruleBox.to_dict()
    elif rule_name is not None:
        rules = client.url_filters.list_rules().to_list()
        for rule_ in rules:
            if rule_.get("name") == rule_name:
                existing_rule = rule_
    if existing_rule is not None:
        id = existing_rule.get("id")
        existing_rule.update(rule)
        existing_rule["id"] = id
    if state == "present":
        if existing_rule is not None:
            """Update"""
            existing_rule = deleteNone(
                dict(
                    rule_id=existing_rule.get("id"),
                    name=existing_rule.get("name"),
                    order=existing_rule.get("order"),
                    protocols=existing_rule.get("protocols"),
                    locations=existing_rule.get("locations"),
                    groups=existing_rule.get("groups"),
                    departments=existing_rule.get("departments"),
                    users=existing_rule.get("users"),
                    url_categories=existing_rule.get("url_categories"),
                    state=existing_rule.get("rule_state"),
                    time_windows=existing_rule.get("time_windows"),
                    rank=existing_rule.get("rank"),
                    request_methods=existing_rule.get("request_methods"),
                    end_user_notification_url=existing_rule.get(
                        "end_user_notification_url"
                    ),
                    override_users=existing_rule.get("override_users"),
                    override_groups=existing_rule.get("override_users"),
                    block_override=existing_rule.get("block_override"),
                    time_quota=existing_rule.get("time_quota"),
                    size_quota=existing_rule.get("size_quota"),
                    description=existing_rule.get("description"),
                    location_groups=existing_rule.get("location_groups"),
                    labels=existing_rule.get("labels"),
                    validity_start_time=existing_rule.get("validity_start_time"),
                    validity_end_time=existing_rule.get("validity_end_time"),
                    validity_time_zone_id=existing_rule.get("validity_time_zone_id"),
                    last_modified_time=existing_rule.get("last_modified_time"),
                    last_modified_by=existing_rule.get("last_modified_by"),
                    enforce_time_validity=existing_rule.get("enforce_time_validity"),
                    action=existing_rule.get("action"),
                    cipa_rule=existing_rule.get("cipa_rule"),
                )
            )
            existing_rule = client.url_filters.update_rule(**existing_rule).to_dict()
            module.exit_json(changed=True, data=existing_rule)
        else:
            """Create"""
            rule = deleteNone(
                dict(
                    name=rule.get("name"),
                    order=rule.get("order"),
                    protocols=rule.get("protocols"),
                    locations=rule.get("locations"),
                    groups=rule.get("groups"),
                    departments=rule.get("departments"),
                    users=rule.get("users"),
                    url_categories=rule.get("url_categories"),
                    state=rule.get("rule_state"),
                    time_windows=rule.get("time_windows"),
                    rank=rule.get("rank"),
                    request_methods=rule.get("request_methods"),
                    end_user_notification_url=rule.get("end_user_notification_url"),
                    override_users=rule.get("override_users"),
                    override_groups=rule.get("override_users"),
                    block_override=rule.get("block_override"),
                    time_quota=rule.get("time_quota"),
                    size_quota=rule.get("size_quota"),
                    description=rule.get("description"),
                    location_groups=rule.get("location_groups"),
                    labels=rule.get("labels"),
                    validity_start_time=rule.get("validity_start_time"),
                    validity_end_time=rule.get("validity_end_time"),
                    validity_time_zone_id=rule.get("validity_time_zone_id"),
                    last_modified_time=rule.get("last_modified_time"),
                    last_modified_by=rule.get("last_modified_by"),
                    enforce_time_validity=rule.get("enforce_time_validity"),
                    action=rule.get("action"),
                    cipa_rule=rule.get("cipa_rule"),
                )
            )
            rule = client.url_filters.add_rule(**rule).to_dict()
            module.exit_json(changed=True, data=rule)
    elif state == "absent":
        if existing_rule is not None:
            code = client.url_filters.delete_rule(rule_id=existing_rule.get("id"))
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_rule)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = zia_argument_spec()
    id_spec = dict(
        type="list",
        elements="str",
        required=False,
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        order=dict(type="int", required=True),
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
            ],
        ),
        locations=id_spec,
        groups=id_spec,
        departments=id_spec,
        users=id_spec,
        url_categories=dict(type="list", elements="str", required=False),
        rule_state=dict(
            type="str",
            required=False,
            default="ENABLED",
            choices=["ENABLED", "DISABLED"],
        ),
        time_windows=id_spec,
        rank=dict(type="int", required=False, default=7),
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
        end_user_notification_url=dict(type="str", required=False),
        override_users=id_spec,
        override_groups=id_spec,
        block_override=dict(type="bool", required=False),
        time_quota=dict(type="int", required=False),
        size_quota=dict(type="int", required=False),
        description=dict(type="str", required=False),
        location_groups=id_spec,
        labels=id_spec,
        validity_start_time=dict(type="int", required=False),
        validity_end_time=dict(type="int", required=False),
        validity_time_zone_id=dict(type="int", required=False),
        last_modified_time=dict(type="int", required=False),
        last_modified_by=id_spec,
        enforce_time_validity=dict(type="bool", required=False),
        action=dict(
            type="str",
            required=False,
            default="ANY",
            choices=["ANY", "NONE", "BLOCK", "CAUTION", "ALLOW", "ICAP_RESPONSE"],
        ),
        cipa_rule=dict(type="bool", required=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
