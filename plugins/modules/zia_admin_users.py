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
short_description: ""
description:
  - ""
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
  role:
    type: list
    elements: dict
    description: "Role of the admin. This is not required for an auditor."
    required: false
    suboptions:
        id:
            description: "Identifier that uniquely identifies an entity"
            required: false
            type: int
        name:
            description: "The configured name of the entity"
            required: false
            type: str
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
"""

RETURN = """
# Returns information on a specified ZIA Admin User.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    zia_argument_spec,
)
from zscaler import ZIA


def core(module: AnsibleModule):
    rule_id = module.params.get("id", None)
    rule_name = module.params.get("name", None)
    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )
    admin_user = dict()
    params = [
        "id",
        "login_name",
        "username",
        "email",
        "comments",
        "role",
        "admin_scope",
        "disabled",
        "is_auditor",
        "password",
        "is_password_login_allowed",
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
    existing_admin_user = service.getByIDOrName(
        admin_user.get("id"), admin_user.get("login_name")
    )
    if existing_admin_user is not None:
        id = existing_admin_user.get("id")
        existing_admin_user.update(admin_user)
        existing_admin_user["id"] = id
    if state == "present":
        if existing_admin_user is not None:
            """Update"""
            service.update(existing_admin_user)
            module.exit_json(changed=True, data=existing_admin_user)
        else:
            """Create"""
            existing_admin_user = service.create(existing_admin_user)
            module.exit_json(changed=False, data=existing_admin_user)
    elif state == "absent":
        if existing_admin_user is not None:
            service.delete(existing_admin_user.get("id"))
            module.exit_json(changed=False, data=existing_admin_user)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    id_name_spec = dict(
        type="list",
        elements="dict",
        options=dict(
            id=dict(type="str", required=False), name=dict(type="str", required=False)
        ),
        required=False,
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        login_name=dict(type="str", required=True),
        username=dict(type="str", required=False),
        email=dict(type="str", required=True),
        comments=dict(type="str", required=False),
        is_non_editable=dict(type="bool", default=False, required=False),
        disabled=dict(type="bool", default=False, required=False),
        is_auditor=dict(type="bool", default=False, required=False),
        password=dict(type="str", required=False),
        is_password_login_allowed=dict(type="bool", default=False, required=False),
        is_security_report_comm_enabled=dict(
            type="bool", default=False, required=False
        ),
        is_service_update_comm_enabled=dict(type="bool", default=False, required=False),
        is_product_update_comm_enabled=dict(type="bool", default=False, required=False),
        is_exec_mobile_app_enabled=dict(type="bool", default=False, required=False),
        role=id_name_spec,
        admin_scope=dict(
            type="list",
            elements="dict",
            options=dict(
                scope_group_member_entities=dict(type="str"),
                id=dict(type="int", required=False),
                scope_entities=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        id=dict(type="int"),
                    ),
                    required=False,
                ),
                type=dict(
                    type="str",
                    required=True,
                    default="ORGANIZATION",
                    choices=[
                        "ORGANIZATION",
                        "DEPARTMENT",
                        "LOCATION",
                        "LOCATION_GROUP",
                    ],
                ),
            ),
            required=False,
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
