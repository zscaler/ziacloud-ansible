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

DOCUMENTATION = r"""
---
module: zia_dlp_web_rules
short_description: "Adds a new DLP policy rule."
description: "Adds a new DLP policy rule."
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
  enabled:
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
    description: "Indicates whether a Zscaler Incident Receiver is associated to the DLP policy rule."
    required: false
    type: bool
  severity:
    description: Indicates the severity selected for the DLP rule violation.
    required: false
    type: str
    choices:
        - RULE_SEVERITY_HIGH
        - RULE_SEVERITY_MEDIUM
        - RULE_SEVERITY_LOW
        - RULE_SEVERITY_INFO
  sub_rules:
    description:
      - The list of exception rules added to a parent rule
      - All attributes within the WebDlpRule model are applicable to the sub-rules. Values for each rule are specified by using the WebDlpRule object.
      - Exception rules can be configured only when the inline DLP rule evaluation type is set to evaluate all DLP rules in the DLP Advanced Settings.
    type: list
    elements: str
    required: false
  parent_rule:
    description:
      - The unique identifier of the parent rule under which an exception rule is added.
    required: false
    type: int
"""

EXAMPLES = r"""
- name: Create/Update/Delete DLP Web Rules
  zscaler.ziacloud.zia_dlp_web_rules:
    provider: '{{ zia_cloud }}'
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
    """
    Normalize rule data by setting computed values.
    """
    normalized = rule.copy()

    computed_values = []
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


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
        "enabled",
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
        "dlp_download_scan_enabled",
        "zcc_notifications_enabled",
        "user_risk_score_levels",
        "severity",
        "parent_rule",
        "sub_rules",
    ]
    for param_name in params:
        rule[param_name] = module.params.get(param_name, None)

    # Validation logic for file_types
    ocr_enabled = rule.get("ocr_enabled", False)
    without_content_inspection = rule.get("without_content_inspection", False)
    file_types = rule.get("file_types") or []  # Defaults to an empty list if None

    valid_types_for_ocr = ["BITMAP", "JPEG", "PNG", "TIFF"]

    # Check for OCR enabled and without content inspection conditions
    if ocr_enabled and not without_content_inspection:
        if not all(file_type in valid_types_for_ocr for file_type in file_types):
            # Invalid condition, fail with detailed error message
            module.fail_json(
                msg="Supported file types with OCR enabled are: "
                + ", ".join(valid_types_for_ocr)
            )

    # Check for ALL_OUTBOUND file type and external DLP engine condition
    if "ALL_OUTBOUND" in file_types:
        if rule.get("dlp_engines") and not without_content_inspection:
            # Valid condition, continue processing
            pass
        else:
            module.fail_json(
                msg="ALL_OUTBOUND file type is only valid with an external DLP engine and without content inspection disabled."
            )

    # Ensure file_types is a list of strings
    if rule.get("file_types"):
        rule["file_types"] = [file_types for file_types in rule["file_types"]]

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

    # Normalize and compare existing and desired data
    desired_rule = normalize_dlp_rule(rule)
    current_rule = normalize_dlp_rule(existing_rule) if existing_rule else {}

    def preprocess_rules(rule, params):
        """
        Preprocess specific attributes in the rule based on their type and structure.
        :param rule: Dict containing the rule data.
        :param params: List of attribute names to be processed.
        :return: Preprocessed rule.
        """
        for attr in params:
            if attr in rule:
                value = rule[attr]

                # Handle list attributes
                if isinstance(value, list):
                    # Extract IDs if list contains dictionaries with 'id'
                    if all(isinstance(item, dict) and "id" in item for item in value):
                        rule[attr] = [item["id"] for item in value]
                    else:
                        # Sort lists for consistent order
                        rule[attr] = sorted(value)

                # Handle dictionary attributes, specifically icap_server
                elif isinstance(value, dict) and attr == "icap_server":
                    # Extract ID if present, else set to empty dictionary
                    rule[attr] = value.get("id", {})

                # Handle attributes that should default to a certain value if not provided
                elif attr in [
                    "min_size",
                    "match_only",
                    "dlp_download_scan_enabled",
                    "zcc_notifications_enabled",
                    "zscaler_incident_receiver",
                ]:
                    if value is None:
                        # Set to default value if not provided
                        if attr == "min_size":
                            rule[attr] = 0
                        elif attr in [
                            "match_only",
                            "dlp_download_scan_enabled",
                            "zcc_notifications_enabled",
                            "zscaler_incident_receiver",
                        ]:
                            rule[attr] = False

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

        # Special handling for lists of IDs like locations and others
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

    # Log the final payload for debugging
    module.warn(f"Final payload being sent to SDK: {rule}")
    if state == "present":
        if existing_rule is not None:
            if differences_detected:
                """Update"""
                update_rule = deleteNone(
                    dict(
                        rule_id=existing_rule.get("id"),
                        name=existing_rule.get("name"),
                        description=existing_rule.get("description"),
                        order=existing_rule.get("order"),
                        protocols=existing_rule.get("protocols"),
                        rank=existing_rule.get("rank"),
                        action=existing_rule.get("action"),
                        enabled=existing_rule.get("enabled"),
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
                        external_auditor_email=existing_rule.get(
                            "external_auditor_email"
                        ),
                        notification_template=existing_rule.get(
                            "notification_template"
                        ),
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
                        user_risk_score_levels=existing_rule.get(
                            "user_risk_score_levels"
                        ),
                        severity=existing_rule.get("severity"),
                        parent_rule=existing_rule.get("parent_rule"),
                        sub_rules=existing_rule.get("sub_rules"),
                    )
                )
                module.warn("Payload Update for SDK: {}".format(update_rule))
                updated_rule = client.web_dlp.update_rule(**update_rule).to_dict()
                module.exit_json(changed=True, data=updated_rule)
        else:
            # Log to check if we are attempting to create a new rule
            module.warn("Creating new rule as no existing rule found")
            """Create"""
            create_rule = deleteNone(
                dict(
                    name=rule.get("name"),
                    description=rule.get("description"),
                    order=rule.get("order"),
                    rank=rule.get("rank"),
                    action=rule.get("action"),
                    enabled=rule.get("enabled"),
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
                    dlp_download_scan_enabled=rule.get("dlp_download_scan_enabled"),
                    zcc_notifications_enabled=rule.get("zcc_notifications_enabled"),
                    user_risk_score_levels=rule.get("user_risk_score_levels"),
                    severity=rule.get("severity"),
                    parent_rule=rule.get("parent_rule"),
                    sub_rules=rule.get("sub_rules"),
                )
            )
            module.warn("Payload for SDK: {}".format(create_rule))
            new_rule = client.web_dlp.add_rule(**create_rule).to_dict()
            module.exit_json(changed=True, data=new_rule)
    elif (
        state == "absent"
        and existing_rule is not None
        and existing_rule.get("id") is not None
    ):
        code = client.web_dlp.delete_rule(rule_id=existing_rule.get("id"))
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
    argument_spec.update(
        id=dict(type="str", required=False),
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
        protocols=dict(type="list", elements="str", required=False),
        url_categories=dict(type="list", elements="str", required=False),
        cloud_applications=dict(type="list", elements="str", required=False),
        sub_rules=dict(type="list", elements="str", required=False),
        external_auditor_email=dict(type="str", required=False),
        min_size=dict(type="int", required=False),
        parent_rule=dict(type="int", required=False),
        match_only=dict(type="bool", required=False),
        without_content_inspection=dict(type="bool", required=False),
        ocr_enabled=dict(type="bool", required=False),
        zscaler_incident_receiver=dict(type="bool", required=False),
        zcc_notifications_enabled=dict(type="bool", required=False),
        dlp_download_scan_enabled=dict(type="bool", required=False),
        icap_server=dict(
            type="dict",
            options=dict(id=dict(type="int", required=True)),
            required=False,
        ),
        action=dict(
            type="str",
            required=False,
            default="NONE",
            choices=["ANY", "NONE", "BLOCK", "ALLOW", "ICAP_RESPONSE"],
        ),
        user_risk_score_levels=dict(
            type="list",
            elements="str",
            required=False,
            choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        ),
        severity=dict(
            type="list",
            elements="str",
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
            choices=[
                "ALL_OUTBOUND",
                "BITMAP",
                "JPEG",
                "PNG",
                "TIFF",
                "MSC",
                "ASM",
                "MATLAB_FILES",
                "SAS",
                "SCALA",
                "BCP",
                "TABLEAU_FILES",
                "DELPHI",
                "APPLE_DOCUMENTS",
                "COMPILED_HTML_HELP",
                "MS_RTF",
                "MS_MDB",
                "DMD",
                "POWERSHELL",
                "DAT",
                "LOG_FILES",
                "XAML",
                "ACCDB",
                "MAKE_FILES",
                "JAVA_FILES",
                "RUBY_FILES",
                "MS_CPP_FILES",
                "PERL_FILES",
                "MS_EXCEL",
                "BASH_SCRIPTS",
                "MS_MSG",
                "CHEMDRAW_FILES",
                "PDF_DOCUMENT",
                "F_FILES",
                "APPX",
                "INCLUDE_FILES",
                "EML_FILES",
                "SC",
                "MS_WORD",
                "QLIKVIEW_FILES",
                "PYTHON",
                "CP",
                "RPY",
                "FOR",
                "INF",
                "YAML_FILES",
                "SHELL_SCRAP",
                "VISUAL_BASIC_SCRIPT",
                "BASIC_SOURCE_CODE",
                "SCT",
                "VISUAL_CPP_FILES",
                "JAVASCRIPT",
                "SCZIP",
                "DSP",
                "RES_FILES",
                "AU3",
                "MM",
                "CSX",
                "WINDOWS_META_FORMAT",
                "OAB",
                "TXT",
                "CML",
                "C_FILES",
                "COBOL",
                "RSP",
                "TLI",
                "VSDX",
                "WINDOWS_SCRIPT_FILES",
                "POSTSCRIPT",
                "JAVA_APPLET",
                "FORM_DATA_POST",
                "TLH",
                "MS_POWERPOINT",
                "SQL",
                "X1B",
                "POD",
                "GO_FILES",
                "NATVIS",
                "CSV",
                "VISUAL_BASIC_FILES",
                "BORLAND_CPP_FILES",
                "IFC",
            ],
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
