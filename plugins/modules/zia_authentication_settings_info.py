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
module: zia_authentication_settings_info
short_description: "Retrieves the organization's default authentication settings information"
description:
  - "Retrieves the organization's default authentication settings information"
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options: {}
"""

EXAMPLES = r"""
- name: Retrieves the organization's default authentication settings information
  zscaler.ziacloud.zia_authentication_settings_info:
    provider: '{{ provider }}'
"""

RETURN = r"""
auth:
  description: A list of rule labels fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    org_auth_type:
      description: The unique identifier for the rule label.
      returned: always
      type: str
      sample: ANY
    one_time_auth:
      description: The name of the rule label.
      returned: always
      type: str
      sample: OTP_DISABLED
    saml_enabled:
      description: Whether or not to authenticate users using SAML Single Sign-On.
      returned: always
      type: bool
      sample: false
    kerberos_enabled:
      description: Whether or not to authenticate users using Kerberos.
      returned: always
      type: bool
      sample: false
    kerberos_pwd:
      description: Can only be set through the generate KerberosPassword
      returned: always
      type: str
      sample: None
    auth_frequency:
      description: How frequently users are required to authenticate e.g., cookie expiration duration.
      returned: always
      type: str
      sample: DAILY_COOKIE
    auth_custom_frequency:
      description: How frequently users are required to authenticate e.g., cookie expiration duration.
      returned: always
      type: int
      sample: 80
    password_strength:
      description: Password strength for form-based authentication.
      returned: always
      type: str
      sample: STRONG
    password_expiry:
      description: Password expiration required for form-based authentication of hosted DB users.
      returned: always
      type: str
      sample: SIX_MONTHS
    last_sync_start_time:
      description: Epoch timestamp representing start of last LDAP sync.
      returned: always
      type: int
      sample: 587556687
    last_sync_end_time:
      description: Epoch timestamp representing end of last LDAP sync.
      returned: always
      type: int
      sample: 587556687
    mobile_admin_saml_idp_enabled:
      description: Indicates use of Mobile Admin as an IdP.
      returned: always
      type: bool
      sample: false
    auto_provision:
      description: Enables SAML Auto-Provisioning.
      returned: always
      type: bool
      sample: false
    directory_sync_migrate_to_scim_enabled:
      description: Enables migration to SCIM by disabling legacy sync.
      returned: always
      type: bool
      sample: false
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    client = ZIAClientHelper(module)

    auth, _unused, error = client.authentication_settings.get_authentication_settings()
    if error:
        module.fail_json(
            msg=f"Error fetching authentication settings: {to_native(error)}"
        )

    module.exit_json(changed=False, auth=auth.as_dict())


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
