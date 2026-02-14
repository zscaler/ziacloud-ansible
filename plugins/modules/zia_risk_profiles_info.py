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
module: zia_risk_profiles_info
short_description: "Retrieves the cloud application risk profile"
description:
  - "Retrieves the cloud application risk profile"
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

options:
  id:
    description: "The unique identifier for the risk profile."
    type: int
    required: false
  profile_name:
    description: "Cloud application risk profile name"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets all list of risk profile
  zscaler.ziacloud.zia_risk_profiles_info:
    provider: '{{ provider }}'

- name: Gets a list of risk profile by name
  zscaler.ziacloud.zia_risk_profiles_info:
    provider: '{{ provider }}'
    profile_name: "example"

- name: Gets a list of risk profile by ID
  zscaler.ziacloud.zia_risk_profiles_info:
    provider: '{{ provider }}'
    id: 73478
"""

RETURN = r"""
profiles:
  description: A list of risk profiles fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Unique identifier of the risk profile.
      type: int
      returned: always
      sample: 73478
    profile_name:
      description: Cloud application risk profile name.
      type: str
      returned: always
      sample: "RiskProfile_12345"
    profile_type:
      description: Risk profile type. Supported value CLOUD_APPLICATIONS
      type: str
      returned: always
      sample: "CLOUD_APPLICATIONS"
    risk_index:
      description: Risk index scores assigned to cloud applications.
      type: list
      elements: str
      returned: always
      sample: ["1", "2", "3", "4", "5"]
    status:
      description: Application status (e.g., SANCTIONED, UN_SANCTIONED).
      type: str
      returned: always
      sample: "SANCTIONED"
    exclude_certificates:
      description: Whether to include (0) or exclude (1) certificates.
      type: int
      returned: always
      sample: 0
    certifications:
      description: List of certifications associated with the profile.
      type: list
      elements: str
      returned: always
      sample: ["ISO_27001", "CCPA", "CISP", "AICPA"]
    poor_items_of_service:
      description: Filters applications with questionable terms and conditions.
      type: str
      returned: always
      sample: "YES"
    admin_audit_logs:
      description: Indicates support for admin activity audit logs.
      type: str
      returned: always
      sample: "YES"
    data_breach:
      description: Indicates history of reported data breaches.
      type: str
      returned: always
      sample: "YES"
    source_ip_restrictions:
      description: Ability to restrict access by source IP.
      type: str
      returned: always
      sample: "YES"
    mfa_support:
      description: Indicates support for multi-factor authentication.
      type: str
      returned: always
      sample: "YES"
    ssl_pinned:
      description: Indicates use of pinned SSL certificates for validation.
      type: str
      returned: always
      sample: "YES"
    http_security_headers:
      description: Indicates use of standard security headers.
      type: str
      returned: always
      sample: "YES"
    evasive:
      description: Indicates support for evasive access techniques.
      type: str
      returned: always
      sample: "YES"
    dns_caa_policy:
      description: Indicates DNS Certification Authority Authorization policy.
      type: str
      returned: always
      sample: "YES"
    weak_cipher_support:
      description: Indicates use of weak or small key ciphers.
      type: str
      returned: always
      sample: "YES"
    password_strength:
      description: Password strength rating under hosting info.
      type: str
      returned: always
      sample: "GOOD"
    ssl_cert_validity:
      description: Validity period enforcement for SSL certificates.
      type: str
      returned: always
      sample: "YES"
    vulnerability:
      description: Indicates mitigation for known CVEs.
      type: str
      returned: always
      sample: "YES"
    malware_scanning_for_content:
      description: Indicates support for malware scanning on content.
      type: str
      returned: always
      sample: "YES"
    file_sharing:
      description: Indicates support for file sharing features.
      type: str
      returned: always
      sample: "YES"
    ssl_cert_key_size:
      description: Key size of SSL certificates.
      type: str
      returned: always
      sample: "BITS_2048"
    vulnerable_to_heart_bleed:
      description: Indicates vulnerability to Heartbleed.
      type: str
      returned: always
      sample: "YES"
    vulnerable_to_log_jam:
      description: Indicates vulnerability to Logjam.
      type: str
      returned: always
      sample: "YES"
    vulnerable_to_poodle:
      description: Indicates vulnerability to POODLE.
      type: str
      returned: always
      sample: "YES"
    vulnerability_disclosure:
      description: Indicates policy for disclosing vulnerabilities.
      type: str
      returned: always
      sample: "YES"
    support_for_waf:
      description: Indicates support for Web Application Firewalls.
      type: str
      returned: always
      sample: "YES"
    remote_screen_sharing:
      description: Indicates support for remote screen sharing.
      type: str
      returned: always
      sample: "YES"
    sender_policy_framework:
      description: Indicates support for SPF.
      type: str
      returned: always
      sample: "YES"
    domain_keys_identified_mail:
      description: Indicates support for DKIM.
      type: str
      returned: always
      sample: "YES"
    domain_based_message_auth:
      description: Indicates support for DMARC.
      type: str
      returned: always
      sample: "YES"
    data_encryption_in_transit:
      description: List of encryption methods used for data in transit.
      type: list
      elements: str
      returned: always
      sample: ["TLSV1_0", "TLSV1_1", "SSLV3"]
    custom_tags:
      description: List of user-defined custom tags for filtering.
      type: list
      elements: dict
      returned: always
      sample: []
    create_time:
      description: Timestamp when the profile was created (epoch seconds).
      type: int
      returned: always
      sample: 1746251637
    last_mod_time:
      description: Timestamp of the last profile modification (epoch seconds).
      type: int
      returned: always
      sample: 1746253320
    modified_by:
      description: User or system who last modified the profile.
      type: dict
      returned: always
      contains:
        id:
          type: int
          description: ID of the modifier.
          sample: 19475409
        name:
          type: str
          description: Name of the modifier.
          sample: "GO_SDK_API"
        external_id:
          type: bool
          description: Indicates if the ID is external.
          sample: false
        extensions:
          type: dict
          description: Additional metadata fields.
          returned: always
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    profile_id = module.params.get("profile_id")
    profile_name = module.params.get("profile_name")

    client = ZIAClientHelper(module)
    profiles = []

    if profile_id is not None:
        profile_obj, _unused, error = client.risk_profiles.get_risk_profile(profile_id)
        if error or profile_obj is None:
            module.fail_json(msg=f"Failed to retrieve Risk Profile with ID '{profile_id}': {to_native(error)}")
        profiles = [profile_obj.as_dict()]
    else:
        query_params = {}
        if profile_name:
            query_params["search"] = profile_name

        result, _unused, error = client.risk_profiles.list_risk_profiles(query_params=query_params)
        if error:
            module.fail_json(msg=f"Error retrieving Risk Profiles: {to_native(error)}")

        profile_list = [g.as_dict() for g in result] if result else []

        if profile_name:
            matched = next((g for g in profile_list if g.get("profile_name") == profile_name), None)
            if not matched:
                available = [g.get("profile_name") for g in profile_list]
                module.fail_json(msg=f"Risk Profile with name '{profile_name}' not found. Available profiles: {available}")
            profiles = [matched]
        else:
            profiles = profile_list

    module.exit_json(changed=False, profiles=profiles)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        profile_name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["profile_name", "id"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
