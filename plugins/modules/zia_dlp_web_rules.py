#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, Zscaler Technology Alliances <zscaler-partner-labs@z-bd.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_dlp_web_rules
short_description: "Adds a new DLP policy rule."
description: "Adds a new DLP policy rule."
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
    description: "The unique identifier for the DLP policy rule."
    required: false
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
    required: true
    type: int
  protocols:
    description: "The protocol criteria specified for the DLP policy rule"
    required: false
    type: str
    choices:
        - "ANY_RULE"
        - "FTP_RULE"
        - "HTTPS_RULE"
        - "HTTP_RULE"
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
  file_types:
    description: "The list of file types to which the DLP policy rule must be applied."
    required: false
    type: str
  cloud_applications:
    description: "The list of cloud applications to which the DLP policy rule must be applied."
    required: false
    type: str
  min_size:
    description: "The minimum file size (in KB) used for evaluation of the DLP policy rule.."
    required: true
    type: int
  action:
    description: "The action taken when traffic matches the DLP policy rule criteria."
    required: false
    type: str
    choices:
        - "ANY"
        - "NONE"
        - "BLOCK"
        - "ALLOW"
        - "ICAP_RESPONSE"
  rule_state:
    description:
        - Enables or disables the DLP policy rule.
    required: false
    type: str
    choices:
        - DISABLED
        - ENABLED
    default: ENABLED
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
    description: "The DLP server, using ICAP, to which the transaction content is forwarded."
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
  ocr_enabled:
    description: "Enables or disables image file scanning."
    required: false
    type: bool
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
    description: "Indicates whether a Zscaler Incident Receiver is associated to the DLP policy rule.."
    required: false
    type: bool
"""

EXAMPLES = """
- name: Gather Information Details of a ZIA User Role
  zscaler.ziacloud.zia_dlp_web_rules:

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
        "rule_state",
        "time_windows",
        "auditor",
        "external_auditor_email",
        "notification_template",
        "match_only",
        "icap_server",
        "without_content_inspection",
        "labels",
        "ocr_enabled",
        "excluded_groups",
        "excluded_departments",
        "excluded_users",
        "zscaler_incident_receiver",
    ]
    for param_name in params:
        rule[param_name] = module.params.get(param_name, None)
    rule_id = rule.get("id", None)
    rule_name = rule.get("name", None)
    existing_rule = None
    if rule_id is not None:
        ruleBox = client.web_dlp.get_rule(rule_id=rule_id)
        if ruleBox is not None:
            existing_rule = ruleBox.to_dict()
    elif rule_name is not None:
        rules = client.web_dlp.list_rules().to_list()
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
                    description=existing_rule.get("description"),
                    order=existing_rule.get("order"),
                    src_ips=existing_rule.get("protocols"),
                    rank=existing_rule.get("rank"),
                    action=existing_rule.get("action"),
                    state=existing_rule.get("rule_state"),
                    locations=existing_rule.get("locations"),
                    location_groups=existing_rule.get("location_groups"),
                    groups=existing_rule.get("groups"),
                    departments=existing_rule.get("departments"),
                    users=existing_rule.get("users"),
                    url_categories=existing_rule.get("url_categories"),
                    dlp_engines=existing_rule.get("dlp_engines"),
                    file_types=existing_rule.get("file_types"),
                    cloud_applications=existing_rule.get("cloud_applications"),
                    min_size=existing_rule.get("min_size"),
                    time_windows=existing_rule.get("time_windows"),
                    auditor=existing_rule.get("auditor"),
                    external_auditor_email=existing_rule.get("external_auditor_email"),
                    notification_template=existing_rule.get("notification_template"),
                    match_only=existing_rule.get("match_only"),
                    icap_server=existing_rule.get("icap_server"),
                    without_content_inspection=existing_rule.get(
                        "without_content_inspection"
                    ),
                    labels=existing_rule.get("labels"),
                    ocr_enabled=existing_rule.get("ocr_enabled"),
                    excluded_groups=existing_rule.get("excluded_groups"),
                    excluded_departments=existing_rule.get("excluded_departments"),
                    excluded_users=existing_rule.get("excluded_users"),
                    zscaler_incident_receiver=existing_rule.get(
                        "zscaler_incident_receiver"
                    ),
                )
            )
            existing_rule = client.web_dlp.update_rule(**existing_rule).to_dict()
            module.exit_json(changed=True, data=existing_rule)
        else:
            """Create"""
            rule = deleteNone(
                dict(
                    name=rule.get("name"),
                    description=rule.get("description"),
                    order=rule.get("order"),
                    rank=rule.get("rank"),
                    action=rule.get("action"),
                    state=rule.get("rule_state"),
                    protocols=rule.get("protocols"),
                    locations=rule.get("locations"),
                    location_groups=rule.get("location_groups"),
                    groups=rule.get("groups"),
                    departments=rule.get("departments"),
                    users=rule.get("users"),
                    url_categories=rule.get("url_categories"),
                    dlp_engines=rule.get("dlp_engines"),
                    file_types=rule.get("file_types"),
                    cloud_applications=rule.get("cloud_applications"),
                    min_size=rule.get("min_size"),
                    time_windows=rule.get("time_windows"),
                    auditor=rule.get("auditor"),
                    external_auditor_email=rule.get("external_auditor_email"),
                    notification_template=rule.get("notification_template"),
                    match_only=rule.get("match_only"),
                    icap_server=rule.get("icap_server"),
                    without_content_inspection=rule.get("without_content_inspection"),
                    labels=rule.get("labels"),
                    ocr_enabled=rule.get("ocr_enabled"),
                    excluded_groups=rule.get("excluded_groups"),
                    excluded_departments=rule.get("excluded_departments"),
                    excluded_users=rule.get("excluded_users"),
                    zscaler_incident_receiver=rule.get("zscaler_incident_receiver"),
                )
            )
            rule = client.web_dlp.add_rule(**rule).to_dict()
            module.exit_json(changed=True, data=rule)
    elif state == "absent":
        if existing_rule is not None:
            code = client.web_dlp.delete_rule(rule_id=existing_rule.get("id"))
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
        description=dict(type="str", required=False),
        order=dict(type="int", required=True),
        rank=dict(type="int", required=False, default=7),
        protocols=dict(type="list", elements="str", required=False),
        action=dict(
            type="str",
            required=False,
            default="NONE",
            choices=["ANY", "NONE", "BLOCK", "ALLOW", "ICAP_RESPONSE"],
        ),
        rule_state=dict(
            type="str",
            required=False,
            default="ENABLED",
            choices=["ENABLED", "DISABLED"],
        ),
        min_size=dict(type="int", required=False),
        match_only=dict(type="bool", required=False),
        without_content_inspection=dict(type="bool", required=False),
        ocr_enabled=dict(type="bool", required=False),
        zscaler_incident_receiver=dict(type="bool", required=False),
        external_auditor_email=dict(type="str", required=False),
        url_categories=dict(type="list", elements="str", required=False),
        file_types=dict(type="list", elements="str", required=False),
        cloud_applications=dict(type="list", elements="str", required=False),
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
        icap_server=id_spec,
        excluded_groups=id_spec,
        excluded_departments=id_spec,
        excluded_users=id_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
