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
module: zia_casb_dlp_rules
short_description: "Manages CASB DLP rules"
description:
  - "Adds, updates, or removes SaaS Security Data at Rest Scanning DLP rules."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
    - C(type) and C(name) are required for create. C(type) with C(id) or C(name) for update/delete.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description:
      - The unique identifier for the CASB DLP rule.
      - Used to reference an existing rule for update or delete.
    required: false
    type: int
  name:
    description: Rule name.
    required: true
    type: str
  type:
    description:
      - The type of SaaS Security Data at Rest Scanning DLP rule.
    required: true
    type: str
    choices:
      - OFLCASB_DLP_FILE
      - OFLCASB_DLP_EMAIL
      - OFLCASB_DLP_CRM
      - OFLCASB_DLP_ITSM
      - OFLCASB_DLP_COLLAB
      - OFLCASB_DLP_REPO
      - OFLCASB_DLP_STORAGE
      - OFLCASB_DLP_GENAI
  description:
    description: An admin editable text-based description of the rule.
    required: false
    type: str
  order:
    description:
      - Order of rule execution with respect to other SaaS Security Data at Rest Scanning DLP rules.
    required: true
    type: int
  rank:
    description:
      - Admin rank assigned to this rule. Mandatory when admin rank-based access restriction is enabled.
    required: false
    type: int
  enabled:
    description:
      - Administrative state of the rule.
      - If C(true), rule is ENABLED. If C(false), rule is DISABLED.
    required: false
    type: bool
  action:
    description: The configured action for the policy rule.
    required: false
    type: str
    choices:
      - OFLCASB_DLP_REPORT_INCIDENT
      - OFLCASB_DLP_SHARE_READ_ONLY
      - OFLCASB_DLP_EXTERNAL_SHARE_READ_ONLY
      - OFLCASB_DLP_INTERNAL_SHARE_READ_ONLY
      - OFLCASB_DLP_REMOVE_PUBLIC_LINK_SHARE
      - OFLCASB_DLP_REVOKE_SHARE
      - OFLCASB_DLP_REMOVE_EXTERNAL_SHARE
      - OFLCASB_DLP_REMOVE_INTERNAL_SHARE
      - OFLCASB_DLP_REMOVE_COLLABORATORS
      - OFLCASB_DLP_REMOVE_INTERNAL_LINK_SHARE
      - OFLCASB_DLP_REMOVE_DISCOVERABLE
      - OFLCASB_DLP_NOTIFY_END_USER
      - OFLCASB_DLP_APPLY_MIP_TAG
      - OFLCASB_DLP_APPLY_BOX_TAG
      - OFLCASB_DLP_MOVE_TO_RESTRICTED_FOLDER
      - OFLCASB_DLP_REMOVE
      - OFLCASB_DLP_QUARANTINE
      - OFLCASB_DLP_APPLY_EMAIL_TAG
      - OFLCASB_DLP_APPLY_GOOGLEDRIVE_LABEL
      - OFLCASB_DLP_REMOVE_EXT_COLLABORATORS
      - OFLCASB_DLP_QUARANTINE_TO_USER_ROOT_FOLDER
      - OFLCASB_DLP_APPLY_WATERMARK
      - OFLCASB_DLP_REMOVE_WATERMARK
      - OFLCASB_DLP_APPLY_HEADER
      - OFLCASB_DLP_APPLY_FOOTER
      - OFLCASB_DLP_APPLY_HEADER_FOOTER
      - OFLCASB_DLP_REMOVE_HEADER
      - OFLCASB_DLP_REMOVE_FOOTER
      - OFLCASB_DLP_REMOVE_HEADER_FOOTER
      - OFLCASB_DLP_BLOCK
      - OFLCASB_DLP_APPLY_ATLASSIAN_CLASSIFICATION_LABEL
      - OFLCASB_DLP_ALLOW
      - OFLCASB_DLP_REDACT
  severity:
    description: The severity level of the incidents that match the policy rule.
    required: false
    type: str
    choices:
      - RULE_SEVERITY_HIGH
      - RULE_SEVERITY_MEDIUM
      - RULE_SEVERITY_LOW
      - RULE_SEVERITY_INFO
  bucket_owner:
    description:
      - A user who inspects their buckets for sensitive data.
      - When you choose a user, their buckets are available in the Buckets field.
    required: false
    type: str
  external_auditor_email:
    description: Email address of the external auditor to whom the DLP email alerts are sent.
    required: false
    type: str
  content_location:
    description: The location for the content that the Zscaler service inspects for sensitive data.
    required: false
    type: str
    choices:
      - CONTENT_LOCATION_PRIVATE_CHANNEL
      - CONTENT_LOCATION_PUBLIC_CHANNEL
      - CONTENT_LOCATION_SHARED_CHANNEL
      - CONTENT_LOCATION_DIRECT_MESSAGE
      - CONTENT_LOCATION_MULTI_PERSON_DIRECT_MESSAGE
  recipient:
    description: Specifies if the email recipient is internal or external.
    required: false
    type: str
  quarantine_location:
    description:
      - Location where all the quarantined files are moved and necessary actions are taken.
    required: false
    type: str
  watermark_delete_old_version:
    description: Specifies whether to delete an old version of the watermarked file.
    required: false
    type: bool
  include_criteria_domain_profile:
    description:
      - If true, criteria_domain_profiles is included as part of the criteria, else excluded.
    required: false
    type: bool
  include_email_recipient_profile:
    description:
      - If true, email_recipient_profiles is included as part of the criteria, else excluded.
    required: false
    type: bool
  without_content_inspection:
    description: If true, Content Matching is set to None.
    required: false
    type: bool
  include_entity_groups:
    description:
      - If true, entity_groups is included as part of the criteria, else excluded.
    required: false
    type: bool
  domains:
    description:
      - The domain for the external organization sharing the channel.
      - Only applicable when content_location is C(CONTENT_LOCATION_SHARED_CHANNEL).
    required: false
    type: list
    elements: str
  cloud_app_tenant_ids:
    description: List of cloud application tenant IDs for which the rule is applied.
    required: false
    type: list
    elements: int
  entity_group_ids:
    description: List of entity group IDs that are part of the rule criteria.
    required: false
    type: list
    elements: int
  included_domain_profile_ids:
    description: List of domain profile IDs included in the criteria for the rule.
    required: false
    type: list
    elements: int
  excluded_domain_profile_ids:
    description: List of domain profile IDs excluded from the criteria for the rule.
    required: false
    type: list
    elements: int
  criteria_domain_profile_ids:
    description: List of domain profile IDs that are mandatory in the criteria.
    required: false
    type: list
    elements: int
  email_recipient_profile_ids:
    description: List of recipient profile IDs for which the rule is applied.
    required: false
    type: list
    elements: int
  object_type_ids:
    description: List of object type IDs for which the rule is applied.
    required: false
    type: list
    elements: int
  labels:
    description: List of rule label IDs associated with the rule.
    required: false
    type: list
    elements: int
  dlp_engines:
    description: List of DLP engine IDs to which the DLP policy rule must be applied.
    required: false
    type: list
    elements: int
  buckets:
    description: List of bucket IDs for the Zscaler service to inspect for sensitive data.
    required: false
    type: list
    elements: int
  groups:
    description: List of group IDs for which the rule is applied.
    required: false
    type: list
    elements: int
  departments:
    description: List of department IDs for which the rule is applied.
    required: false
    type: list
    elements: int
  users:
    description: List of user IDs for which the rule is applied.
    required: false
    type: list
    elements: int
  collaboration_scope:
    description: Collaboration scope for the rule.
    required: false
    type: list
    elements: str
  file_types:
    description: File types for which the rule is applied. If not set, applied across all file types.
    required: false
    type: list
    elements: str
  components:
    description:
      - List of components for which the rule is applied.
      - Zscaler service inspects these components for sensitive data.
    required: false
    type: list
    elements: str
  zscaler_incident_receiver:
    description: Zscaler Incident Receiver details. Provide as dict with C(id) key.
    required: false
    type: dict
  receiver:
    description: Details of the DLP Incident Receiver, Provide as dict with C(id) key.
    required: false
    type: dict
  auditor_notification:
    description: Notification template for DLP email alerts. Provide as dict with C(id) key.
    required: false
    type: dict
  tag:
    description: Tag applied to the rule. Provide as dict with C(id) key.
    required: false
    type: dict
  watermark_profile:
    description: Watermark profile applied to the rule. Provide as dict with C(id) key.
    required: false
    type: dict
  redaction_profile:
    description: Redaction profile in the criteria. Provide as dict with C(id) key.
    required: false
    type: dict
  casb_email_label:
    description: Email label associated with the rule. Provide as dict with C(id) key.
    required: false
    type: dict
  casb_tombstone_template:
    description: Quarantine tombstone template. Provide as dict with C(id) key.
    required: false
    type: dict
"""

EXAMPLES = r"""
- name: Create a CASB DLP rule
  zscaler.ziacloud.zia_casb_dlp_rules:
    provider: '{{ provider }}'
    name: "My DLP Rule"
    type: OFLCASB_DLP_ITSM
    order: 1
    description: "Rule created by Ansible"
    action: OFLCASB_DLP_REPORT_INCIDENT
    severity: RULE_SEVERITY_HIGH
    components:
      - COMPONENT_ITSM_OBJECTS
      - COMPONENT_ITSM_ATTACHMENTS
    collaboration_scope:
      - ANY
    file_types:
      - FTCATEGORY_APPX
      - FTCATEGORY_SQL

- name: Update a CASB DLP rule by ID
  zscaler.ziacloud.zia_casb_dlp_rules:
    provider: '{{ provider }}'
    id: 1070199
    type: OFLCASB_DLP_ITSM
    name: "Updated Rule Name"
    order: 1

- name: Delete a CASB DLP rule
  zscaler.ziacloud.zia_casb_dlp_rules:
    provider: '{{ provider }}'
    id: 1070199
    type: OFLCASB_DLP_ITSM
    state: absent
"""

RETURN = r"""
data:
  description: The CASB DLP rule resource record.
  returned: on success
  type: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)

RULE_TYPE_CHOICES = [
    "OFLCASB_DLP_FILE",
    "OFLCASB_DLP_EMAIL",
    "OFLCASB_DLP_CRM",
    "OFLCASB_DLP_ITSM",
    "OFLCASB_DLP_COLLAB",
    "OFLCASB_DLP_REPO",
    "OFLCASB_DLP_STORAGE",
    "OFLCASB_DLP_GENAI",
]

ACTION_CHOICES = [
    "OFLCASB_DLP_REPORT_INCIDENT",
    "OFLCASB_DLP_SHARE_READ_ONLY",
    "OFLCASB_DLP_EXTERNAL_SHARE_READ_ONLY",
    "OFLCASB_DLP_INTERNAL_SHARE_READ_ONLY",
    "OFLCASB_DLP_REMOVE_PUBLIC_LINK_SHARE",
    "OFLCASB_DLP_REVOKE_SHARE",
    "OFLCASB_DLP_REMOVE_EXTERNAL_SHARE",
    "OFLCASB_DLP_REMOVE_INTERNAL_SHARE",
    "OFLCASB_DLP_REMOVE_COLLABORATORS",
    "OFLCASB_DLP_REMOVE_INTERNAL_LINK_SHARE",
    "OFLCASB_DLP_REMOVE_DISCOVERABLE",
    "OFLCASB_DLP_NOTIFY_END_USER",
    "OFLCASB_DLP_APPLY_MIP_TAG",
    "OFLCASB_DLP_APPLY_BOX_TAG",
    "OFLCASB_DLP_MOVE_TO_RESTRICTED_FOLDER",
    "OFLCASB_DLP_REMOVE",
    "OFLCASB_DLP_QUARANTINE",
    "OFLCASB_DLP_APPLY_EMAIL_TAG",
    "OFLCASB_DLP_APPLY_GOOGLEDRIVE_LABEL",
    "OFLCASB_DLP_REMOVE_EXT_COLLABORATORS",
    "OFLCASB_DLP_QUARANTINE_TO_USER_ROOT_FOLDER",
    "OFLCASB_DLP_APPLY_WATERMARK",
    "OFLCASB_DLP_REMOVE_WATERMARK",
    "OFLCASB_DLP_APPLY_HEADER",
    "OFLCASB_DLP_APPLY_FOOTER",
    "OFLCASB_DLP_APPLY_HEADER_FOOTER",
    "OFLCASB_DLP_REMOVE_HEADER",
    "OFLCASB_DLP_REMOVE_FOOTER",
    "OFLCASB_DLP_REMOVE_HEADER_FOOTER",
    "OFLCASB_DLP_BLOCK",
    "OFLCASB_DLP_APPLY_ATLASSIAN_CLASSIFICATION_LABEL",
    "OFLCASB_DLP_ALLOW",
    "OFLCASB_DLP_REDACT",
]

# Attributes that are compared for idempotency (exclude computed/read-only)
CASB_DLP_RULE_ATTRIBUTES = [
    "name",
    "description",
    "order",
    "rank",
    "enabled",
    "action",
    "severity",
    "bucket_owner",
    "external_auditor_email",
    "content_location",
    "recipient",
    "quarantine_location",
    "watermark_delete_old_version",
    "include_criteria_domain_profile",
    "include_email_recipient_profile",
    "without_content_inspection",
    "include_entity_groups",
    "domains",
    "cloud_app_tenant_ids",
    "entity_group_ids",
    "included_domain_profile_ids",
    "excluded_domain_profile_ids",
    "criteria_domain_profile_ids",
    "email_recipient_profile_ids",
    "object_type_ids",
    "labels",
    "dlp_engines",
    "buckets",
    "groups",
    "departments",
    "users",
    "collaboration_scope",
    "file_types",
    "components",
    "zscaler_incident_receiver",
    "receiver",
    "auditor_notification",
    "tag",
    "watermark_profile",
    "redaction_profile",
    "casb_email_label",
    "casb_tombstone_template",
]

# API returns nested objects (e.g. cloudAppTenants); module uses simple ID lists (cloud_app_tenant_ids).
# Map API response keys to module param keys for normalization/comparison.
API_TO_MODULE_MAP = {
    "cloud_app_tenants": "cloud_app_tenant_ids",
    "object_types": "object_type_ids",
    "included_domain_profiles": "included_domain_profile_ids",
    "excluded_domain_profiles": "excluded_domain_profile_ids",
    "criteria_domain_profiles": "criteria_domain_profile_ids",
    "email_recipient_profiles": "email_recipient_profile_ids",
    "entity_groups": "entity_group_ids",
}

# SDK uses different param names (e.g. cloud_app_tenant_ids -> cloudAppTenants via reformat)
# The SDK transform_common_id_fields handles conversion, we pass snake_case
ID_LIST_ATTRS = [
    "cloud_app_tenant_ids",
    "entity_group_ids",
    "included_domain_profile_ids",
    "excluded_domain_profile_ids",
    "criteria_domain_profile_ids",
    "email_recipient_profile_ids",
    "object_type_ids",
    "labels",
    "dlp_engines",
    "buckets",
    "groups",
    "departments",
    "users",
]


def _normalize_list(val):
    """Normalize list for order-independent comparison."""
    if val is None:
        return None
    if isinstance(val, list):
        return sorted([str(x) for x in val]) if val else []
    return val


def _extract_ids(val):
    """
    Extract IDs from list of refs (dicts with id) or list of ints.
    Skip dicts without 'id' (API may return partial objects like status/features_supported only).
    Also check tenant_id / zscaler_app_tenant_id for CasbTenant-like objects.
    """
    if val is None:
        return None
    if not isinstance(val, list):
        return val
    ids = []
    for item in val:
        if isinstance(item, dict):
            # Prefer explicit id; fallback to tenant_id / zscalerAppTenantId for CasbTenant refs
            vid = item.get("id")
            if vid is not None:
                ids.append(int(vid))
            else:
                tid = item.get("tenant_id") or item.get("tenantId")
                if tid is not None:
                    ids.append(int(tid))
                else:
                    zid = item.get("zscaler_app_tenant_id") or item.get("zscalerAppTenantId")
                    if zid is not None and isinstance(zid, (int, float)):
                        ids.append(int(zid))
        elif isinstance(item, (int, float)):
            ids.append(int(item))
    ids = [x for x in ids if x is not None]
    return sorted(ids)


def _normalize_single_ref(val):
    """Normalize single ref (dict with id) for comparison."""
    if val is None:
        return None
    if isinstance(val, dict) and "id" in val:
        return {"id": val["id"]}
    return val


def normalize_casb_rule(rule):
    """Normalize rule dict for comparison."""
    if not rule:
        return {}
    norm = rule.copy()
    norm.pop("id", None)
    norm.pop("last_modified_time", None)
    # Map API response keys (nested objects) to module param keys (ID lists)
    for api_key, module_key in API_TO_MODULE_MAP.items():
        if api_key in norm:
            norm[module_key] = _extract_ids(norm.pop(api_key))
    # Convert state to enabled for comparison
    if "state" in norm and norm["state"]:
        norm["enabled"] = norm["state"] == "ENABLED"
        norm.pop("state", None)
    for key in ID_LIST_ATTRS:
        if key in norm:
            norm[key] = _extract_ids(norm[key])
    # String lists: normalize for order-independent comparison (sorted)
    for key in ("domains", "collaboration_scope", "file_types", "components"):
        if key in norm:
            norm[key] = _normalize_list(norm[key])
    for key in (
        "zscaler_incident_receiver",
        "auditor_notification",
        "tag",
        "watermark_profile",
        "redaction_profile",
        "casb_email_label",
        "casb_tombstone_template",
    ):
        if key in norm:
            norm[key] = _normalize_single_ref(norm[key])
    return norm


def _build_rule_params(module):
    """Build params dict from module, mapping to SDK expected format."""
    params = {"type": module.params.get("type")}
    for attr in CASB_DLP_RULE_ATTRIBUTES:
        val = module.params.get(attr)
        if val is not None:
            if attr == "enabled":
                params["enabled"] = val
            else:
                params[attr] = val
    # SDK requires enabled->state for add/update; API fails without it (500).
    # Default to enabled=True when state=present and not explicitly set.
    if module.params.get("state") == "present" and "enabled" not in params:
        params["enabled"] = True
    return params


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    rule_id = module.params.get("id")
    rule_name = module.params.get("name")
    rule_type = module.params.get("type")

    rule_params = _build_rule_params(module)

    existing_rule = None
    raw_response_body = None  # Raw API body for extracting IDs lost by SDK (e.g. cloudAppTenants)

    if rule_id is not None:
        result, response, error = client.casb_dlp_rules.get_rule(rule_id, rule_type)
        if error:
            module.fail_json(msg=f"Error fetching CASB DLP rule with id {rule_id}: {to_native(error)}")
        existing_rule = result.as_dict() if result else None
        if response and hasattr(response, "get_body"):
            raw_response_body = response.get_body()
    else:
        result, response, error = client.casb_dlp_rules.list_rules(rule_type)
        if error:
            module.fail_json(msg=f"Error listing CASB DLP rules: {to_native(error)}")
        rules_list = [r.as_dict() for r in result] if result else []
        if rule_name:
            for i, r in enumerate(rules_list):
                if r.get("name") == rule_name:
                    existing_rule = r
                    # Get raw body for this rule from response (SDK loses id in CasbTenant)
                    if response and hasattr(response, "get_results"):
                        raw_items = response.get_results()
                        if raw_items and i < len(raw_items):
                            raw_response_body = raw_items[i]
                    break

    # SDK CasbTenant model drops "id" from cloudAppTenants; use raw API body when available
    if existing_rule and raw_response_body:
        raw_tenants = raw_response_body.get("cloudAppTenants") or raw_response_body.get("cloud_app_tenants")
        if raw_tenants:
            extracted = _extract_ids(raw_tenants)
            if extracted:
                existing_rule["cloud_app_tenant_ids"] = extracted
                existing_rule.pop("cloud_app_tenants", None)

    normalized_desired = normalize_casb_rule(rule_params)
    normalized_existing = normalize_casb_rule(existing_rule) if existing_rule else {}

    differences_detected = False
    for key, value in normalized_desired.items():
        existing_val = normalized_existing.get(key)
        if key in ID_LIST_ATTRS:
            if _extract_ids(value) != _extract_ids(existing_val):
                differences_detected = True
                module.warn(f"Difference in {key}. Current: {existing_val}, Desired: {value}")
        elif key in ("domains", "collaboration_scope", "file_types", "components"):
            if _normalize_list(value) != _normalize_list(existing_val):
                differences_detected = True
                module.warn(f"Difference in {key}. Current: {existing_val}, Desired: {value}")
        elif existing_val != value:
            differences_detected = True
            module.warn(f"Difference in {key}. Current: {existing_val}, Desired: {value}")

    if module.check_mode:
        if state == "present" and (existing_rule is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_rule:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_rule:
            if differences_detected:
                id_to_update = existing_rule.get("id")
                if not id_to_update:
                    module.fail_json(msg="Cannot update: ID is missing from the existing rule.")

                updated, _unused, error = client.casb_dlp_rules.update_rule(
                    id_to_update,
                    **rule_params,
                )
                if error:
                    module.fail_json(msg=f"Error updating CASB DLP rule: {to_native(error)}")
                module.exit_json(changed=True, data=updated.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule)
        else:
            new_rule, _unused, error = client.casb_dlp_rules.add_rule(**rule_params)
            if error:
                import json

                payload_preview = json.dumps(
                    {k: v for k, v in rule_params.items() if "password" not in k.lower() and "secret" not in k.lower()},
                    default=str,
                    indent=2,
                )
                module.fail_json(
                    msg=f"Error adding CASB DLP rule: {to_native(error)}",
                    payload_sent=rule_params,
                    payload_preview=payload_preview,
                )
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            id_to_delete = existing_rule.get("id")
            if not id_to_delete:
                module.fail_json(msg="Cannot delete: ID is missing from the existing rule.")

            _unused, _unused, error = client.casb_dlp_rules.delete_rule(
                id_to_delete,
                rule_type,
            )
            if error:
                module.fail_json(msg=f"Error deleting CASB DLP rule: {to_native(error)}")
            module.exit_json(changed=True, data=existing_rule)
        else:
            module.exit_json(changed=False, data={})

    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            id=dict(type="int", required=False),
            name=dict(type="str", required=True),
            type=dict(type="str", required=True, choices=RULE_TYPE_CHOICES),
            description=dict(type="str", required=False),
            order=dict(type="int", required=True),
            rank=dict(type="int", required=False),
            enabled=dict(type="bool", required=False),
            action=dict(type="str", required=False, choices=ACTION_CHOICES),
            severity=dict(
                type="str",
                required=False,
                choices=[
                    "RULE_SEVERITY_HIGH",
                    "RULE_SEVERITY_MEDIUM",
                    "RULE_SEVERITY_LOW",
                    "RULE_SEVERITY_INFO",
                ],
            ),
            receiver=dict(type="dict", required=False),
            bucket_owner=dict(type="str", required=False),
            external_auditor_email=dict(type="str", required=False),
            content_location=dict(
                type="str",
                required=False,
                choices=[
                    "CONTENT_LOCATION_PRIVATE_CHANNEL",
                    "CONTENT_LOCATION_PUBLIC_CHANNEL",
                    "CONTENT_LOCATION_SHARED_CHANNEL",
                    "CONTENT_LOCATION_DIRECT_MESSAGE",
                    "CONTENT_LOCATION_MULTI_PERSON_DIRECT_MESSAGE",
                ],
            ),
            recipient=dict(type="str", required=False),
            quarantine_location=dict(type="str", required=False),
            watermark_delete_old_version=dict(type="bool", required=False),
            include_criteria_domain_profile=dict(type="bool", required=False),
            include_email_recipient_profile=dict(type="bool", required=False),
            without_content_inspection=dict(type="bool", required=False),
            include_entity_groups=dict(type="bool", required=False),
            domains=dict(type="list", elements="str", required=False),
            cloud_app_tenant_ids=dict(type="list", elements="int", required=False),
            entity_group_ids=dict(type="list", elements="int", required=False),
            included_domain_profile_ids=dict(type="list", elements="int", required=False),
            excluded_domain_profile_ids=dict(type="list", elements="int", required=False),
            criteria_domain_profile_ids=dict(type="list", elements="int", required=False),
            email_recipient_profile_ids=dict(type="list", elements="int", required=False),
            object_type_ids=dict(type="list", elements="int", required=False),
            labels=dict(type="list", elements="int", required=False),
            dlp_engines=dict(type="list", elements="int", required=False),
            buckets=dict(type="list", elements="int", required=False),
            groups=dict(type="list", elements="int", required=False),
            departments=dict(type="list", elements="int", required=False),
            users=dict(type="list", elements="int", required=False),
            collaboration_scope=dict(type="list", elements="str", required=False),
            file_types=dict(type="list", elements="str", required=False),
            components=dict(type="list", elements="str", required=False),
            zscaler_incident_receiver=dict(type="dict", required=False),
            auditor_notification=dict(type="dict", required=False),
            tag=dict(type="dict", required=False),
            watermark_profile=dict(type="dict", required=False),
            redaction_profile=dict(type="dict", required=False),
            casb_email_label=dict(type="dict", required=False),
            casb_tombstone_template=dict(type="dict", required=False),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
