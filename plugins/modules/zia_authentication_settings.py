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
module: zia_authentication_settings
short_description: Updates the organization's default authentication settings
description:
  - Updates the organization's default authentication settings in the ZIA Admin Portal.
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
  - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.modified_state

options:
  org_auth_type:
    description:
      - User authentication type. If set to an LDAP-based value, the LDAP configuration must also be valid.
    type: str
    choices:
      - ANY
      - NONE
      - SAFECHANNEL_DIR
      - MICROSOFT_ACTIVE_DIR
      - OPENLDAP_DIR
      - NOVELL_DIR
      - IBM_DOMINO_DIR
      - SUN_DIR
      - SMAUTH_ENTERPRISE_HOSTED
    required: false

  one_time_auth:
    description:
      - Controls how one-time passwords are handled when org_auth_type is NONE.
    type: str
    choices:
      - OTP_DISABLED
      - OTP_TOKEN
      - OTP_LINK
    required: false

  saml_enabled:
    description:
      - Whether SAML authentication is enabled.
    type: bool
    required: false

  kerberos_enabled:
    description:
      - Whether Kerberos authentication is enabled.
    type: bool
    required: false

  auth_frequency:
    description:
      - Defines how frequently users must reauthenticate.
    type: str
    choices:
      - DAILY_COOKIE
      - PERMANENT_COOKIE
      - SESSION_COOKIE
      - CUSTOM_COOKIE
    required: false

  auth_custom_frequency:
    description:
      - The custom cookie authentication frequency in days. Required if auth_frequency is CUSTOM_COOKIE.
    type: int
    required: false

  password_strength:
    description:
      - Enforces minimum password strength for hosted DB user authentication.
    type: str
    choices:
      - NONE
      - MEDIUM
      - STRONG
    required: false

  password_expiry:
    description:
      - Defines how often user passwords expire.
    type: str
    choices:
      - NEVER
      - ONE_MONTH
      - THREE_MONTHS
      - SIX_MONTHS
    required: false

  last_sync_start_time:
    description:
      - Timestamp for when the last LDAP directory sync started (epoch time).
    type: int
    required: false

  last_sync_end_time:
    description:
      - Timestamp for when the last LDAP directory sync completed (epoch time).
    type: int
    required: false

  mobile_admin_saml_idp_enabled:
    description:
      - Whether Mobile Admin can be used as an identity provider.
    type: bool
    required: false

  auto_provision:
    description:
      - Whether to enable SAML-based user auto-provisioning.
    type: bool
    required: false

  directory_sync_migrate_to_scim_enabled:
    description:
      - If true, disables legacy LDAP sync to migrate to SCIM-based provisioning.
    type: bool
    required: false

  state:
    description:
      - Whether the resource should be present. Only C(present) is supported.
    type: str
    choices: [present]
    default: present
"""

EXAMPLES = r"""
- name: Updates the organization's default authentication settings information
  zscaler.ziacloud.zia_authentication_settings:
    provider: '{{ provider }}'
    org_auth_type: true
    one_time_auth: false
    saml_enabled: false
    kerberos_enabled: false
    auth_frequency: DAILY_COOKIE
    auth_custom_frequency: false
    password_strength: MEDIUM
    password_expiry: SIX_MONTHS
    mobile_admin_saml_idp_enabled: false
    auto_provision: false
    directory_sync_migrate_to_scim_enabled: false
"""

RETURN = r"""
#  Authentication settings Configured.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    convert_keys_to_snake_case,
)


def core(module):
    state = module.params.get("state")
    if state != "present":
        module.fail_json(msg="Only 'present' is supported for this module.")

    client = ZIAClientHelper(module)

    # Define the supported malware fields
    params = [
        "org_auth_type",
        "one_time_auth",
        "saml_enabled",
        "kerberos_enabled",
        "auth_frequency",
        "auth_custom_frequency",
        "password_strength",
        "password_expiry",
        "last_sync_start_time",
        "last_sync_end_time",
        "mobile_admin_saml_idp_enabled",
        "auto_provision",
        "directory_sync_migrate_to_scim_enabled",
    ]

    # Filter only explicitly set values
    settings_data = {k: module.params.get(k) for k in params if module.params.get(k) is not None}

    current_settings, _unused, error = client.authentication_settings.get_authentication_settings()
    if error:
        module.fail_json(msg=f"Error fetching authentication settings: {to_native(error)}")

    # Extract raw config from SDK and convert keys to snake_case
    raw_response = getattr(current_settings, "_raw_config", {})
    current_dict = convert_keys_to_snake_case(raw_response)

    drift = any(current_dict.get(k) != settings_data.get(k) for k in settings_data)

    module.warn(f"📦 Raw SDK response: {current_settings}")
    module.warn(f"🐍 Snake_case converted: {current_dict}")
    module.warn(f"🔍 Current settings: {current_dict}")
    module.warn(f"📥 Desired settings: {settings_data}")
    module.warn(f"🧠 Drift detected: {drift}")

    if module.check_mode:
        module.exit_json(changed=drift)

    if drift:
        for k, v in settings_data.items():
            setattr(current_settings, k, v)

        updated, _unused, error = client.authentication_settings.update_authentication_settings(current_settings)
        if error:
            module.fail_json(msg=f"Error updating authentication settings: {to_native(error)}")

        module.exit_json(changed=True, auth_settings=updated.as_dict())

    module.exit_json(changed=False, auth_settings=current_dict)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        org_auth_type=dict(
            type="str",
            required=False,
            choices=[
                "ANY",
                "NONE",
                "SAFECHANNEL_DIR",
                "MICROSOFT_ACTIVE_DIR",
                "OPENLDAP_DIR",
                "NOVELL_DIR",
                "IBM_DOMINO_DIR",
                "SUN_DIR",
                "SMAUTH_ENTERPRISE_HOSTED",
            ],
        ),
        one_time_auth=dict(
            type="str",
            required=False,
            choices=["OTP_DISABLED", "OTP_TOKEN", "OTP_LINK"],
        ),
        saml_enabled=dict(type="bool", required=False),
        kerberos_enabled=dict(type="bool", required=False),
        auth_frequency=dict(
            type="str",
            required=False,
            choices=[
                "DAILY_COOKIE",
                "PERMANENT_COOKIE",
                "SESSION_COOKIE",
                "CUSTOM_COOKIE",
            ],
        ),
        auth_custom_frequency=dict(type="int", required=False),
        password_strength=dict(type="str", required=False, choices=["NONE", "MEDIUM", "STRONG"]),
        password_expiry=dict(
            type="str",
            required=False,
            choices=["NEVER", "ONE_MONTH", "THREE_MONTHS", "SIX_MONTHS"],
        ),
        last_sync_start_time=dict(type="int", required=False),
        last_sync_end_time=dict(type="int", required=False),
        mobile_admin_saml_idp_enabled=dict(type="bool", required=False),
        auto_provision=dict(type="bool", required=False),
        directory_sync_migrate_to_scim_enabled=dict(type="bool", required=False),
        state=dict(type="str", choices=["present"], default="present"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
