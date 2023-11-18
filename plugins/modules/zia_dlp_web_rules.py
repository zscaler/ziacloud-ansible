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
extends_documentation_fragment:
    - zscaler.ziacloud.fragments.credentials_set
    - zscaler.ziacloud.fragments.provider
    - zscaler.ziacloud.fragments.enabled_state
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


def normalize_dlp_rule(rule):
    """
    Normalize rule data by setting computed values.
    """
    normalized = rule.copy()

    computed_values = [
        "id",
        "name",
        "description",
        "rank",
        "locations",
        "location_groups",
        "groups",
        "departments",
        "users",
        "dlp_engines",
        "cloud_applications",
        "min_size",
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
    ]
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
        "dlp_download_scan_enabled",
        "zcc_notifications_enabled",
        "user_risk_score_levels",
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

    def preprocess_rules(rule, attributes_to_preprocess):
        """
        Preprocess specific attributes in the rule.
        :param rule: Dict containing the rule data.
        :param attributes_to_preprocess: Dict of attributes that require preprocessing and their expected types.
        :return: Preprocessed rule.
        """
        for attr, attr_type in attributes_to_preprocess.items():
            if attr in rule and isinstance(rule[attr], attr_type):
                if attr_type == list:
                    # Sort lists for consistent order
                    rule[attr] = sorted(rule[attr])
                # Add more conditions here if needed for other types
        return rule

    # Usage in your core function
    attributes_to_handle = {
        "user_risk_score_levels": list,
        "protocols": list,
        "file_types": list,
        "url_categories": list,
        "order": int,
        "action": str,
    }

    existing_rule_preprocessed = preprocess_rules(current_rule, attributes_to_handle)
    desired_rule_preprocessed = preprocess_rules(desired_rule, attributes_to_handle)

    # Then proceed with your comparison logic
    differences_detected = False
    for key, value in desired_rule_preprocessed.items():
        current_value = existing_rule_preprocessed.get(key)

        # Convert 'state' in current_rule to boolean 'rule_state'
        if key == "rule_state" and "state" in current_rule:
            current_value = current_rule["state"] == "ENABLED"

        if current_value != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_value}, Desired: {value}"
            )

    if existing_rule is not None:
        id = existing_rule.get("id")
        existing_rule.update(rule)
        existing_rule["id"] = id

        # Log the final payload for debugging
        # module.warn(f"Final payload being sent to SDK: {rule}")

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
                        rule_state=existing_rule.get("rule_state"),
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
                    )
                )
                # module.warn("Payload Update for SDK: {}".format(update_rule))
                updated_rule = client.web_dlp.update_rule(**update_rule).to_dict()
                module.exit_json(changed=True, data=updated_rule)
        else:
            # Log to check if we are attempting to create a new rule
            # module.warn("Creating new rule as no existing rule found")
            """Create"""
            create_rule = deleteNone(
                dict(
                    name=rule.get("name"),
                    description=rule.get("description"),
                    order=rule.get("order"),
                    rank=rule.get("rank"),
                    action=rule.get("action"),
                    rule_state=rule.get("rule_state"),
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
                )
            )
            # module.warn("Payload for SDK: {}".format(create_rule))
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
        elements="str",
        required=False,
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        order=dict(type="int", required=False),
        rank=dict(type="int", required=False, default=7),
        protocols=dict(type="list", elements="str", required=False),
        action=dict(
            type="str",
            required=False,
            default="NONE",
            choices=["ANY", "NONE", "BLOCK", "ALLOW", "ICAP_RESPONSE"],
        ),
        rule_state=dict(type="bool", required=False),
        min_size=dict(type="int", required=False),
        match_only=dict(type="bool", required=False),
        without_content_inspection=dict(type="bool", required=False),
        ocr_enabled=dict(type="bool", required=False),
        zscaler_incident_receiver=dict(type="bool", required=False),
        external_auditor_email=dict(type="str", required=False),
        url_categories=dict(type="list", elements="str", required=False),
        user_risk_score_levels=dict(
            type="list",
            elements="str",
            required=False,
            choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
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
