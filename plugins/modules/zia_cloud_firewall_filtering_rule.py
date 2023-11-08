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
module: zia_cloud_firewall_filtering_rule
short_description: "Firewall Filtering policy rule."
description: "Adds a new Firewall Filtering policy rule."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
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
    required: true
    type: int
  rank:
    description: "Admin rank of the Firewall Filtering policy rule"
    required: false
    default: 7
    type: int
  locations:
    description: "The locations to which the Firewall Filtering policy rule applies"
    type: list
    elements: str
    required: false
  location_groups:
    description: "The location groups to which the Firewall Filtering policy rule applies"
    type: list
    elements: str
    required: false
  departments:
    description: "The departments to which the Firewall Filtering policy rule applies"
    type: list
    elements: str
    required: false
  groups:
    description: "The groups to which the Firewall Filtering policy rule applies"
    type: list
    elements: str
    required: false
  users:
    description: "The users to which the Firewall Filtering policy rule applies"
    type: list
    elements: str
    required: false
  time_windows:
    description: "The time interval in which the Firewall Filtering policy rule applies"
    type: list
    elements: str
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
  rule_state:
    description:
        - Determines whether the Firewall Filtering policy rule is enabled or disabled
    required: false
    type: str
    choices:
        - DISABLED
        - ENABLED
    default: ENABLED
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
  app_services:
    description: "Application services on which this rule is applied"
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
  default_rule:
    description: "If set to true, the default rule is applied"
    type: bool
    required: false
    default: false
  predefined:
    description: "If set to true, a predefined rule is applied"
    type: bool
    required: false
    default: false
"""

EXAMPLES = """
- name: Gather Information Details of a ZIA User Role
  zscaler.ziacloud.zia_device_group_facts:

- name: Gather Information Details of a ZIA Admin User by Name
  zscaler.ziacloud.zia_device_group_facts:
    name: "IOS"
"""

RETURN = """
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


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    rule = dict()
    params = [
        "id",
        "name",
        "order",
        "rank",
        "locations",
        "location_groups",
        "departments",
        "groups",
        "users",
        "time_windows",
        "action",
        "state",
        "description",
        "enable_full_logging",
        "src_ips",
        "src_ip_groups",
        "dest_addresses",
        "dest_ip_categories",
        "dest_countries",
        "dest_ip_groups",
        "nw_services",
        "nw_service_groups",
        "nw_applications",
        "nw_application_groups",
        "app_services",
        "app_service_groups",
        "labels",
        "default_rule",
        "predefined",
    ]
    for param_name in params:
        rule[param_name] = module.params.get(param_name, None)
    rule_id = rule.get("id", None)
    rule_name = rule.get("name", None)
    existing_rule = None
    if rule_id is not None:
        ruleBox = client.firewall.get_rule(rule_id=rule_id)
        if ruleBox is not None:
            existing_rule = ruleBox.to_dict()
    elif rule_name is not None:
        rules = client.firewall.list_rules().to_list()
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
                    rank=existing_rule.get("rank"),
                    action=existing_rule.get("action"),
                    state=existing_rule.get("rule_state"),
                    description=existing_rule.get("description"),
                    enable_full_logging=existing_rule.get("enable_full_logging"),
                    src_ips=existing_rule.get("src_ips"),
                    dest_addresses=existing_rule.get("dest_addresses"),
                    dest_ip_categories=existing_rule.get("dest_ip_categories"),
                    dest_countries=existing_rule.get("dest_countries"),
                    default_rule=existing_rule.get("default_rule"),
                    predefined=existing_rule.get("predefined"),
                    nw_applications=existing_rule.get("nw_applications"),
                    dest_ip_groups=existing_rule.get("dest_ip_groups"),
                    nw_services=existing_rule.get("nw_services"),
                    nw_service_groups=existing_rule.get("nw_service_groups"),
                    nw_application_groups=existing_rule.get("nw_application_groups"),
                    app_services=existing_rule.get("app_services"),
                    app_service_groups=existing_rule.get("app_service_groups"),
                    labels=existing_rule.get("labels"),
                    locations=existing_rule.get("locations"),
                    location_groups=existing_rule.get("location_groups"),
                    departments=existing_rule.get("departments"),
                    groups=existing_rule.get("groups"),
                    users=existing_rule.get("users"),
                    time_windows=existing_rule.get("time_windows"),
                    src_ip_groups=existing_rule.get("src_ip_groups"),
                )
            )
            existing_rule = client.firewall.update_rule(**existing_rule).to_dict()
            module.exit_json(changed=True, data=existing_rule)
        else:
            """Create"""
            rule = deleteNone(
                dict(
                    name=rule.get("name"),
                    order=rule.get("order"),
                    rank=rule.get("rank"),
                    action=rule.get("action"),
                    state=rule.get("rule_state"),
                    description=rule.get("description"),
                    enable_full_logging=rule.get("enable_full_logging"),
                    src_ips=rule.get("src_ips"),
                    dest_addresses=rule.get("dest_addresses"),
                    dest_ip_categories=rule.get("dest_ip_categories"),
                    dest_countries=rule.get("dest_countries"),
                    default_rule=rule.get("default_rule"),
                    predefined=rule.get("predefined"),
                    nw_applications=rule.get("nw_applications"),
                    dest_ip_groups=rule.get("dest_ip_groups"),
                    nw_services=rule.get("nw_services"),
                    nw_service_groups=rule.get("nw_service_groups"),
                    nw_application_groups=rule.get("nw_application_groups"),
                    app_services=rule.get("app_services"),
                    app_service_groups=rule.get("app_service_groups"),
                    labels=rule.get("labels"),
                    locations=rule.get("locations"),
                    location_groups=rule.get("location_groups"),
                    departments=rule.get("departments"),
                    groups=rule.get("groups"),
                    users=rule.get("users"),
                    time_windows=rule.get("time_windows"),
                    src_ip_groups=rule.get("src_ip_groups"),
                )
            )
            rule = client.firewall.add_rule(**rule).to_dict()
            module.exit_json(changed=True, data=rule)
    elif state == "absent":
        if existing_rule is not None:
            code = client.firewall.delete_rule(rule_id=existing_rule.get("id"))
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_rule)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    id_spec = dict(
        type="list",
        elements="str",
        required=False,
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        order=dict(type="int", required=True),
        rank=dict(type="int", required=False, default=7),
        action=dict(
            type="str",
            required=False,
            default="ALLOW",
            choices=["ALLOW", "BLOCK_DROP", "BLOCK_RESET", "BLOCK_ICMP", "EVAL_NWAPP"],
        ),
        description=dict(type="str", required=True),
        rule_state=dict(
            type="str",
            required=False,
            default="ENABLED",
            choices=["ENABLED", "DISABLED"],
        ),
        src_ips=dict(type="list", elements="str", required=False),
        dest_addresses=dict(type="list", elements="str", required=False),
        dest_ip_categories=dict(type="list", elements="str", required=False),
        dest_countries=dict(type="list", elements="str", required=False),
        default_rule=dict(type="bool", required=False),
        predefined=dict(type="bool", required=False),
        enable_full_logging=dict(type="bool", required=False),
        nw_applications=id_spec,
        dest_ip_groups=id_spec,
        nw_services=id_spec,
        nw_service_groups=id_spec,
        nw_application_groups=id_spec,
        app_services=id_spec,
        app_service_groups=id_spec,
        labels=id_spec,
        locations=id_spec,
        location_groups=id_spec,
        departments=id_spec,
        groups=id_spec,
        users=id_spec,
        time_windows=id_spec,
        src_ip_groups=id_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
