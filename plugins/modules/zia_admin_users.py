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
module: zia_admin_user
short_description: "Creates an admin or auditor user."
description:
  - Creates an admin or auditor user.
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
options:
  id:
    description: "Admin role Id."
    required: false
    type: int
  login_name:
    description:
        - Admin or auditor's login name.
        - LoginName is in email format and uses the domain name associated to the Zscaler account.
    required: true
    type: str
  username:
    description: Admin or auditor's username.
    required: true
    type: str
  email:
    description: Admin or auditor's email address
    required: true
    type: str
  role_id:
    description: "Role of the admin. This is not required for an auditor."
    required: false
    type: str
    description: "Role of the admin. This is not required for an auditor."
    required: false
  comments:
    description: "Additional information about the admin or auditor."
    required: false
    type: str
  admin_scope:
    type: list
    elements: dict
    description:
        - The admin's scope.
          A scope is required for admins, but not applicable to auditors.
          This attribute is subject to change.
        - An admin's scope can be limited to certain resources, policies, or reports.
          An admin's scope can be limited by LOCATION, LOCATION GROUP, or DEPARTMENT.
          If this is not specified, then the admin has an ORGANIZATION scope by default.
    required: false
    suboptions:
        scope_group_member_entities:
            type: list
            elements: dict
            required: false
            description:
            - Only applicable for the LOCATION_GROUP admin scope type.
              This attribute gives the list of ID/name pairs of locations within the location group.
              The attribute name is subject to change.
            suboptions:
                id:
                description: "Identifier that uniquely identifies an entity"
                required: false
                type: int
                name:
                    description: "The configured name of the entity"
                    required: false
                    type: str
        type:
            description:
                - The admin scope type. The attribute name is subject to change.
            required: false
            type: str
            choices:
              - ORGANIZATION
              - DEPARTMENT
              - LOCATION
              - LOCATION_GROUP
        scope_entities:
            type: list
            elements: dict
            required: false
            description:
            - Based on the admin scope type, the entities can be the ID/name pair of departments, locations, or location groups.
            - The attribute name is subject to change.
            suboptions:
                id:
                description: "Identifier that uniquely identifies an entity"
                required: false
                type: int
                name:
                    description: "The configured name of the entity"
                    required: false
                    type: str
  is_non_editable:
    description:
      - Indicates whether or not the admin can be edited or deleted.
    type: bool
    default: false
  disabled:
    description:
      - Indicates whether or not the admin account is disabled.
    type: bool
  is_auditor:
    description:
      - Indicates whether the user is an auditor. This attribute is subject to change.
    type: bool
    default: false
  password:
    description:
        - The admin's password.
        - If admin single sign-on (SSO) is disabled, then this field is mandatory for POST requests.
        - This information is not provided in a GET response."
    type: str
  is_password_login_allowed:
    description:
        - The default is true when SAML Authentication is disabled
        - When SAML Authentication is enabled, this can be set to false in order to force the admin to login via SSO only.
    type: bool
    default: false
  is_security_report_comm_enabled:
    description:
        - Communication for Security Report is enabled.
    type: bool
    default: false
  is_service_update_comm_enabled:
    description:
        - Communication setting for Service Update.
    type: bool
    default: false
  is_product_update_comm_enabled:
    description:
        - Communication setting for Product Update.
    type: bool
    default: false
  is_password_expired:
    description:
        - Indicates whether or not an admin's password has expired.
    type: bool
    default: false
  is_exec_mobile_app_enabled:
    description:
        - Indicates whether or not Executive Insights App access is enabled for the admin.
    type: bool
    default: false
  state:
    description:
      - Whether the app connector group should be present or absent.
    type: str
    choices:
        - present
        - absent
    default: present
"""

EXAMPLES = """
- name: Create Second Application Server
  zscaler.ziacloud.zia_admin_user:
    login_name: "john.smith@acme.com"
    username: "John Smith"
    email: "john.smith@acme.com"
    is_password_login_allowed: true
    password: ""
    is_security_report_comm_enabled: true
    is_service_update_comm_enabled: true
    is_product_update_comm_enabled: true
    comments: "Administrator Group"
    role_id: 1234567
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


def normalize_admin_user(admin):
    """
    Normalize admin user data by setting computed values.
    """
    normalized = admin.copy()

    computed_values = [
        "id",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    admin_user = dict()
    params = [
        "id",
        "login_name",
        "username",
        "email",
        "comments",
        "role_id",
        "admin_scope_type",
        "disabled",
        "is_auditor",
        "password",
        "is_security_report_comm_enabled",
        "is_service_update_comm_enabled",
        "is_product_update_comm_enabled",
        "is_exec_mobile_app_enabled",
        "is_password_login_allowed",
        "is_password_expired",
        "is_non_editable",
    ]
    for param_name in params:
        admin_user[param_name] = module.params.get(param_name, None)
    user_id = admin_user.get("id", None)
    login_name = admin_user.get("login_name", None)

    existing_user = None
    if user_id is not None:
        existing_user = client.admin_and_role_management.get_user(user_id).to_dict()
    else:
        admin_users = client.admin_and_role_management.list_users().to_list()
        if login_name is not None:
            for user in admin_users:
                if user.get("login_name", None) == login_name:
                    existing_user = user
                    break

    # Normalize and compare existing and desired data
    normalized_user = normalize_admin_user(admin_user)
    normalized_existing_user = (
        normalize_admin_user(existing_user) if existing_user else {}
    )

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in normalized_user.items():
        if key not in fields_to_exclude and normalized_existing_user.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing_user.get(key)}, Desired: {value}"
            )

    if existing_user is not None:
        id = existing_user.get("id")
        existing_user.update(normalized_user)
        existing_user["id"] = id

    module.warn(f"Final payload being sent to SDK: {admin_user}")
    if state == "present":
        if existing_user is not None:
            if differences_detected:
                """Update"""
                update_user = deleteNone(
                    dict(
                        user_id=existing_user.get("id"),
                        login_name=existing_user.get("login_name"),
                        name=existing_user.get("username"),
                        password=existing_user.get("password"),
                        email=existing_user.get("email"),
                        comments=existing_user.get("comments"),
                        role_id=existing_user.get("role_id"),
                        disabled=existing_user.get("disabled"),
                        is_auditor=existing_user.get("is_auditor"),
                        is_security_report_comm_enabled=existing_user.get(
                            "is_security_report_comm_enabled"
                        ),
                        is_service_update_comm_enabled=existing_user.get(
                            "is_service_update_comm_enabled"
                        ),
                        is_product_update_comm_enabled=existing_user.get(
                            "is_product_update_comm_enabled"
                        ),
                        is_exec_mobile_app_enabled=existing_user.get(
                            "is_exec_mobile_app_enabled"
                        ),
                        is_password_login_allowed=existing_user.get(
                            "is_password_login_allowed"
                        ),
                        is_password_expired=existing_user.get("is_password_expired"),
                        is_non_editable=existing_user.get("is_non_editable"),
                        admin_scope_type=existing_user.get("admin_scope_type"),
                    )
                )
                module.warn("Payload Update for SDK: {}".format(update_user))
                updated_user = client.admin_and_role_management.update_user(
                    **update_user
                ).to_dict()
                module.exit_json(changed=True, data=updated_user)
        else:
            module.warn("Creating new rule as no existing rule found")
            """Create"""
            create_user = deleteNone(
                dict(
                    login_name=admin_user.get("login_name"),
                    username=admin_user.get("username"),
                    email=admin_user.get("email"),
                    comments=admin_user.get("comments"),
                    role_id=admin_user.get("role_id"),
                    admin_scope=admin_user.get("admin_scope"),
                    disabled=admin_user.get("disabled"),
                    is_auditor=admin_user.get("is_auditor"),
                    password=admin_user.get("password"),
                    is_password_login_allowed=admin_user.get(
                        "is_password_login_allowed"
                    ),
                    is_security_report_comm_enabled=admin_user.get(
                        "is_security_report_comm_enabled"
                    ),
                    is_service_update_comm_enabled=admin_user.get(
                        "is_service_update_comm_enabled"
                    ),
                    is_product_update_comm_enabled=admin_user.get(
                        "is_product_update_comm_enabled"
                    ),
                    is_exec_mobile_app_enabled=admin_user.get(
                        "is_exec_mobile_app_enabled"
                    ),
                    is_password_expired=admin_user.get("is_password_expired"),
                    is_non_editable=admin_user.get("is_non_editable"),
                    admin_scope_type=admin_user.get("admin_scope_type"),
                )
            )
            module.warn("Payload for SDK: {}".format(create_user))
            new_rule = client.admin_and_role_management.add_user(
                **create_user
            ).to_dict()
            module.exit_json(changed=True, data=new_rule)
    elif state == "absent":
        if existing_user is not None:
            code = client.admin_and_role_management.delete_user(existing_user.get("id"))
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_user)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        login_name=dict(type="str", required=True),
        username=dict(type="str", required=False),
        email=dict(type="str", required=True),
        comments=dict(type="str", required=False),
        is_non_editable=dict(type="bool", default=False, required=False),
        disabled=dict(type="bool", default=False, required=False),
        is_auditor=dict(type="bool", default=False, required=False),
        password=dict(type="str", required=True, no_log=True),
        is_password_login_allowed=dict(
            type="bool", default=False, required=False, no_log=True
        ),
        is_security_report_comm_enabled=dict(
            type="bool", default=False, required=False
        ),
        is_service_update_comm_enabled=dict(type="bool", default=False, required=False),
        is_product_update_comm_enabled=dict(type="bool", default=False, required=False),
        is_exec_mobile_app_enabled=dict(type="bool", default=False, required=False),
        role_id=dict(type="int", required=False),
        admin_scope_type=dict(
            type="str",
            required=False,
            default="ORGANIZATION",
            choices=["ORGANIZATION", "DEPARTMENT", "LOCATION", "LOCATION_GROUP"],
        ),
        # admin_scope=dict(
        #     type="list",
        #     elements="dict",
        #     options=dict(
        #         scope_group_member_entities=dict(type="str"),
        #         id=dict(type="int", required=False),
        #         scope_entities=dict(
        #             type="list",
        #             elements="dict",
        #             options=dict(
        #                 id=dict(type="int"),
        #             ),
        #             required=False,
        #         ),
        #         type=dict(
        #             type="str",
        #             required=True,
        #             default="ORGANIZATION",
        #             choices=[
        #                 "ORGANIZATION",
        #                 "DEPARTMENT",
        #                 "LOCATION",
        #                 "LOCATION_GROUP",
        #             ],
        #         ),
        #     ),
        #     required=False,
        # ),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
