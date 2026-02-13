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
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zia_tenant_restriction_profile
short_description: "Manages ZIA tenant restriction profiles"
description:
  - "Creates, updates, or deletes tenant restriction profiles for cloud app control."
  - "Tenant restriction profiles control access to cloud applications (e.g., Microsoft 365, Google)."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
    - Use C(id) or C(name) to reference an existing profile for update/delete.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description:
      - The unique identifier for the tenant restriction profile.
      - Used to reference an existing profile for update or delete.
    required: false
    type: int
  name:
    description:
      - The tenant restriction profile name.
      - Required for create.
    required: true
    type: str
  description:
    description:
      - Additional information about the profile.
    required: false
    type: str
  app_type:
    description:
      - Restricted tenant profile application type.
      - Supported values include YOUTUBE, GOOGLE, MSLOGINSERVICES, SLACK, BOX,
        FACEBOOK, AWS, DROPBOX, WEBEX_LOGIN_SERVICES, AMAZON_S3, ZOHO_LOGIN_SERVICES,
        GOOGLE_CLOUD_PLATFORM, ZOOM, IBMSMARTCLOUD, GITHUB, CHATGPT_AI.
    required: false
    type: str
  item_type_primary:
    description:
      - Tenant profile primary item type.
      - See Zscaler documentation for available item types.
    required: false
    type: str
  item_type_secondary:
    description:
      - Tenant profile secondary item type.
    required: false
    type: str
  restrict_personal_o365_domains:
    description:
      - Flag to restrict personal domains for Office 365.
    required: false
    type: bool
  allow_google_consumers:
    description:
      - Flag to allow Google consumers.
    required: false
    type: bool
  ms_login_services_tr_v2:
    description:
      - Flag to choose between v1 and v2 for MS Login services tenant restriction.
    required: false
    type: bool
  allow_google_visitors:
    description:
      - Flag to allow Google visitors.
    required: false
    type: bool
  allow_gcp_cloud_storage_read:
    description:
      - Flag to allow or disallow GCP cloud storage reads.
    required: false
    type: bool
  item_data_primary:
    description:
      - Tenant profile primary item data (list of strings).
    required: false
    type: list
    elements: str
  item_data_secondary:
    description:
      - Tenant profile secondary item data (list of strings).
    required: false
    type: list
    elements: str
  item_value:
    description:
      - Tenant profile item value for YouTube categories.
      - See Zscaler documentation for available item values.
    required: false
    type: list
    elements: str
"""

EXAMPLES = r"""
- name: Create a tenant restriction profile for Microsoft Login Services
  zscaler.ziacloud.zia_tenant_restriction_profile:
    provider: '{{ provider }}'
    name: "MS Profile 01"
    description: "Restricts to allowed tenants"
    app_type: "MSLOGINSERVICES"
    item_type_primary: "TENANT_RESTRICTION_TENANT_DIRECTORY"
    item_data_primary:
      - "76b66e9c-201a-49dc-bb7e-e9d77604a4c2"
    item_type_secondary: "TENANT_RESTRICTION_TENANT_NAME"
    item_data_secondary:
      - "example.com"
      - "example.org"
    restrict_personal_o365_domains: false
    ms_login_services_tr_v2: true

- name: Update a tenant restriction profile by ID
  zscaler.ziacloud.zia_tenant_restriction_profile:
    provider: '{{ provider }}'
    id: 1254654
    name: "MS Profile 01 Updated"
    description: "Updated description"

- name: Delete a tenant restriction profile
  zscaler.ziacloud.zia_tenant_restriction_profile:
    provider: '{{ provider }}'
    id: 1254654
    state: absent
"""

RETURN = r"""
data:
  description: The tenant restriction profile resource record.
  returned: on success
  type: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def _sorted_list(lst):
    """Return sorted list for idempotent comparison."""
    if not lst:
        return []
    return sorted(str(x) for x in lst)


def _norm_bool(val):
    if val is None:
        return None
    return bool(val)


def normalize_profile(profile):
    """Normalize profile dict for idempotency comparison."""
    if not profile:
        return {}
    return {
        "name": profile.get("name"),
        "description": profile.get("description") or "",
        "app_type": profile.get("app_type") or "",
        "item_type_primary": profile.get("item_type_primary") or "",
        "item_type_secondary": profile.get("item_type_secondary") or "",
        "restrict_personal_o365_domains": _norm_bool(profile.get("restrict_personal_o365_domains")),
        "allow_google_consumers": _norm_bool(profile.get("allow_google_consumers")),
        "ms_login_services_tr_v2": _norm_bool(profile.get("ms_login_services_tr_v2")),
        "allow_google_visitors": _norm_bool(profile.get("allow_google_visitors")),
        "allow_gcp_cloud_storage_read": _norm_bool(profile.get("allow_gcp_cloud_storage_read")),
        "item_data_primary": _sorted_list(profile.get("item_data_primary")),
        "item_data_secondary": _sorted_list(profile.get("item_data_secondary")),
        "item_value": _sorted_list(profile.get("item_value")),
    }


def build_profile_payload(params, existing=None):
    """Build payload for add/update. Merge with existing for update."""
    payload = {
        "name": params.get("name"),
        "description": params.get("description") or "",
        "app_type": params.get("app_type") or "",
        "item_type_primary": params.get("item_type_primary") or "",
        "item_type_secondary": params.get("item_type_secondary") or "",
        "restrict_personal_o365_domains": params.get("restrict_personal_o365_domains") if params.get("restrict_personal_o365_domains") is not None else (existing.get("restrict_personal_o365_domains") if existing else False),
        "allow_google_consumers": params.get("allow_google_consumers") if params.get("allow_google_consumers") is not None else (existing.get("allow_google_consumers") if existing else False),
        "ms_login_services_tr_v2": params.get("ms_login_services_tr_v2") if params.get("ms_login_services_tr_v2") is not None else (existing.get("ms_login_services_tr_v2") if existing else False),
        "allow_google_visitors": params.get("allow_google_visitors") if params.get("allow_google_visitors") is not None else (existing.get("allow_google_visitors") if existing else False),
        "allow_gcp_cloud_storage_read": params.get("allow_gcp_cloud_storage_read") if params.get("allow_gcp_cloud_storage_read") is not None else (existing.get("allow_gcp_cloud_storage_read") if existing else False),
        "item_data_primary": params.get("item_data_primary") if params.get("item_data_primary") is not None else (existing.get("item_data_primary") if existing else []),
        "item_data_secondary": params.get("item_data_secondary") if params.get("item_data_secondary") is not None else (existing.get("item_data_secondary") if existing else []),
        "item_value": params.get("item_value") if params.get("item_value") is not None else (existing.get("item_value") if existing else []),
    }
    if existing and "id" in existing:
        payload["id"] = existing["id"]
    return payload


def core(module):
    state = module.params.get("state")
    profile_id = module.params.get("id")
    profile_name = module.params.get("name")

    client = ZIAClientHelper(module)

    existing_profile = None
    if profile_id is not None:
        result, _unused, error = client.tenancy_restriction_profile.get_restriction_profile(
            profile_id
        )
        if error:
            module.fail_json(
                msg=f"Error fetching tenant restriction profile with id {profile_id}: {to_native(error)}"
            )
        existing_profile = result.as_dict()
    else:
        result, _unused, error = client.tenancy_restriction_profile.list_restriction_profile(
            query_params={"search": profile_name} if profile_name else None
        )
        if error:
            module.fail_json(
                msg=f"Error listing tenant restriction profiles: {to_native(error)}"
            )
        profiles_list = [p.as_dict() for p in result] if result else []
        if profile_name:
            for p in profiles_list:
                if p.get("name", "").lower() == profile_name.lower():
                    existing_profile = p
                    break

    desired = build_profile_payload(module.params, existing_profile)
    normalized_desired = normalize_profile(desired)
    normalized_existing = normalize_profile(existing_profile) if existing_profile else {}
    differences_detected = normalized_desired != normalized_existing

    if module.check_mode:
        if state == "present" and (existing_profile is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_profile:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_profile:
            if differences_detected:
                id_to_update = existing_profile.get("id")
                if not id_to_update:
                    module.fail_json(msg="Cannot update: ID is missing from the existing profile.")
                update_params = {k: v for k, v in desired.items() if k != "id"}
                updated, _unused, error = client.tenancy_restriction_profile.update_restriction_profile(
                    id_to_update, **update_params
                )
                if error:
                    module.fail_json(
                        msg=f"Error updating tenant restriction profile: {to_native(error)}"
                    )
                module.exit_json(changed=True, data=updated.as_dict())
            else:
                module.exit_json(changed=False, data=existing_profile)
        else:
            add_params = {k: v for k, v in desired.items() if k != "id"}
            new_profile, _unused, error = client.tenancy_restriction_profile.add_restriction_profile(
                **add_params
            )
            if error:
                module.fail_json(
                    msg=f"Error creating tenant restriction profile: {to_native(error)}"
                )
            module.exit_json(changed=True, data=new_profile.as_dict())

    elif state == "absent":
        if existing_profile:
            id_to_delete = existing_profile.get("id")
            if not id_to_delete:
                module.fail_json(msg="Cannot delete: ID is missing from the existing profile.")
            _unused, _unused, error = client.tenancy_restriction_profile.delete_restriction_profile(
                id_to_delete
            )
            if error:
                module.fail_json(
                    msg=f"Error deleting tenant restriction profile: {to_native(error)}"
                )
            module.exit_json(changed=True, data=existing_profile)
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
            description=dict(type="str", required=False),
            app_type=dict(type="str", required=False),
            item_type_primary=dict(type="str", required=False),
            item_type_secondary=dict(type="str", required=False),
            restrict_personal_o365_domains=dict(type="bool", required=False),
            allow_google_consumers=dict(type="bool", required=False),
            ms_login_services_tr_v2=dict(type="bool", required=False),
            allow_google_visitors=dict(type="bool", required=False),
            allow_gcp_cloud_storage_read=dict(type="bool", required=False),
            item_data_primary=dict(type="list", elements="str", required=False),
            item_data_secondary=dict(type="list", elements="str", required=False),
            item_value=dict(type="list", elements="str", required=False),
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
