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
module: zia_risk_profiles
short_description: "Adds a new cloud application risk profile"
description:
  - "Adds a new cloud application risk profile"
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
  - zscaler.ziacloud.fragments.state

options:
  id:
    description: "The unique identifier for the risk profile"
    type: int
  profile_name:
    description: "Cloud application risk profile name"
    required: true
    type: str
  profile_type:
    description: "Risk profile type. Supported value: CLOUD_APPLICATIONS"
    type: str
    choices: ["CLOUD_APPLICATIONS"]
  risk_index:
    description: "Risk index scores assigned to cloud applications"
    type: list
    elements: int
  status:
    description: "Application status"
    type: str
    choices: ["UN_SANCTIONED", "SANCTIONED", "ANY"]
  exclude_certificates:
    description: "Whether to include (0) or exclude (1) certificates"
    type: int
  certifications:
    description: "List of compliance certifications for the profile"
    type: list
    elements: str
    choices:
      - CSA_STAR
      - ISO_27001
      - HIPAA
      - FISMA
      - FEDRAMP
      - SOC2
      - ISO_27018
      - PCI_DSS
      - ISO_27017
      - SOC1
      - SOC3
      - GDPR
      - CCPA
      - FERPA
      - COPPA
      - HITECH
      - EU_US_SWISS_PRIVACY_SHIELD
      - EU_US_PRIVACY_SHIELD_FRAMEWORK
      - CISP
      - AICPA
      - FIPS
      - SAFE_BIOPHARMA
      - ISAE_3000
      - SSAE_18
      - NIST
      - ISO_14001
      - SOC
      - TRUSTE
      - ISO_26262
      - ISO_20252
      - RGPD
      - ISO_20243
      - JIS_Q_27001
      - ISO_10002
      - JIS_Q_15001_2017
      - ISMAP
      - GAAP
  poor_items_of_service:
    description: "Flag for questionable legal terms in the service"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  admin_audit_logs:
    description: "Support for admin activity audit logs"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  data_breach:
    description: "History of reported data breaches"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  source_ip_restrictions:
    description: "Support for restricting access by source IP"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  mfa_support:
    description: "Support for multi-factor authentication"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  ssl_pinned:
    description: "Use of pinned SSL certificates"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  http_security_headers:
    description: "Support for standard HTTP security headers"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  evasive:
    description: "Support for anonymous or evasive access"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  dns_caa_policy:
    description: "Presence of a DNS CAA policy"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  weak_cipher_support:
    description: "Support for weak encryption ciphers"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  password_strength:
    description: "Password strength rating in hosting info"
    type: str
    choices: ["ANY", "GOOD", "POOR", "UN_KNOWN"]
  ssl_cert_validity:
    description: "Validity period of SSL certificates"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  vulnerability:
    description: "Mitigation for known CVE vulnerabilities"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  malware_scanning_for_content:
    description: "Support for content malware scanning"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  file_sharing:
    description: "Support for file sharing features"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  ssl_cert_key_size:
    description: "Minimum SSL certificate key size"
    type: str
    choices:
      - ANY
      - UN_KNOWN
      - BITS_2048
      - BITS_256
      - BITS_3072
      - BITS_384
      - BITS_4096
      - BITS_1024
      - BITS_8192
  vulnerable_to_heart_bleed:
    description: "Whether the app is vulnerable to Heartbleed"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  vulnerable_to_log_jam:
    description: "Whether the app is vulnerable to Logjam"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  vulnerable_to_poodle:
    description: "Whether the app is vulnerable to POODLE"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  vulnerability_disclosure:
    description: "Policy or transparency around vulnerability disclosure"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  support_for_waf:
    description: "Support for Web Application Firewalls"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  remote_screen_sharing:
    description: "Support for remote screen sharing capabilities"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  sender_policy_framework:
    description: "Support for Sender Policy Framework (SPF)"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  domain_keys_identified_mail:
    description: "Support for DomainKeys Identified Mail (DKIM)"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  domain_based_message_auth:
    description: "Support for Domain-Based Message Authentication (DMARC)"
    type: str
    choices: ["ANY", "YES", "NO", "UN_KNOWN"]
  data_encryption_in_transit:
    description: "Encryption methods supported for data in transit"
    type: list
    elements: str
    choices:
      - ANY
      - UN_KNOWN
      - TLSV1_0
      - TLSV1_1
      - TLSV1_2
      - TLSV1_3
      - SSLV2
      - SSLV3
  custom_tags:
    description: "List of custom tag blocks to include or exclude"
    type: list
    elements: dict
"""

EXAMPLES = r"""
- name: Configure Risk Profiles
  zscaler.ziacloud.zia_risk_profiles:
    profile_name: "RiskProfile_12345"
    profile_type: "CLOUD_APPLICATIONS"
    status: "SANCTIONED"
    risk_index: [1, 2, 3, 4, 5]
    custom_tags: []
    certifications:
      - AICPA
      - CCPA
      - CISP
      - ISO_27001
    password_strength: "GOOD"
    poor_items_of_service: "YES"
    admin_audit_logs: "YES"
    data_breach: "YES"
    source_ip_restrictions: "YES"
    file_sharing: "YES"
    mfa_support: "YES"
    ssl_pinned: "YES"
    data_encryption_in_transit:
      - SSLV2
      - SSLV3
      - TLSV1_0
      - TLSV1_1
      - TLSV1_2
      - TLSV1_3
      - UN_KNOWN
    http_security_headers: "YES"
    evasive: "YES"
    dns_caa_policy: "YES"
    ssl_cert_validity: "YES"
    weak_cipher_support: "YES"
    vulnerability: "YES"
    vulnerable_to_heart_bleed: "YES"
    ssl_cert_key_size: "BITS_2048"
    vulnerable_to_poodle: "YES"
    support_for_waf: "YES"
    vulnerability_disclosure: "YES"
    domain_keys_identified_mail: "YES"
    malware_scanning_for_content: "YES"
    domain_based_message_auth: "YES"
    sender_policy_framework: "YES"
    remote_screen_sharing: "YES"
    vulnerable_to_log_jam: "YES"
"""

RETURN = r"""
# The newly created risk profile resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_profile(profile):
    """
    Remove computed attributes from a profile dict to make comparison easier.
    """
    normalized = profile.copy() if profile else {}
    computed_values = ["id", "exclude_certificates"]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    risk_profile_params = {
        p: module.params.get(p)
        for p in [
            "id",
            "profile_name",
            "profile_type",
            "risk_index",
            "status",
            "exclude_certificates",
            "certifications",
            "poor_items_of_service",
            "admin_audit_logs",
            "data_breach",
            "source_ip_restrictions",
            "mfa_support",
            "ssl_pinned",
            "http_security_headers",
            "evasive",
            "dns_caa_policy",
            "weak_cipher_support",
            "password_strength",
            "ssl_cert_validity",
            "vulnerability",
            "malware_scanning_for_content",
            "file_sharing",
            "ssl_cert_key_size",
            "vulnerable_to_heart_bleed",
            "vulnerable_to_log_jam",
            "vulnerable_to_poodle",
            "vulnerability_disclosure",
            "support_for_waf",
            "remote_screen_sharing",
            "sender_policy_framework",
            "domain_keys_identified_mail",
            "domain_based_message_auth",
            "data_encryption_in_transit",
            "custom_tags",
        ]
    }
    profile_id = risk_profile_params.get("id")
    profile_name = risk_profile_params.get("profile_name")

    existing_profile = None

    if profile_id:
        result, _unused, error = client.risk_profiles.get_risk_profile(profile_id)
        if error:
            module.fail_json(
                msg=f"Error fetching profile with id {profile_id}: {to_native(error)}"
            )
        existing_profile = result.as_dict()
    else:
        result, _unused, error = client.risk_profiles.list_risk_profiles()
        if error:
            module.fail_json(msg=f"Error listing profiles: {to_native(error)}")
        profile_list = [profile.as_dict() for profile in result]
        if profile_name:
            for profile in profile_list:
                if profile.get("profile_name") == profile_name:
                    existing_profile = profile
                    break

    normalized_desired = normalize_profile(risk_profile_params)
    normalized_existing = (
        normalize_profile(existing_profile) if existing_profile else {}
    )

    unordered_fields = [
        "risk_index",
        "certifications",
        "data_encryption_in_transit",
        "custom_tags",
    ]

    differences_detected = False
    for key, value in normalized_desired.items():
        current_value = normalized_existing.get(key)

        # Ignore order for specific list fields
        if (
            key in unordered_fields
            and isinstance(value, list)
            and isinstance(current_value, list)
        ):
            if set(map(str, value)) != set(map(str, current_value)):
                differences_detected = True
                module.warn(
                    f"Difference detected in {key}. Current: {current_value}, Desired: {value}"
                )
        else:
            if current_value != value:
                differences_detected = True
                module.warn(
                    f"Difference detected in {key}. Current: {current_value}, Desired: {value}"
                )

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
                profile_id_to_update = existing_profile.get("id")
                if not profile_id_to_update:
                    module.fail_json(
                        msg="Cannot update profile: ID is missing from the existing resource."
                    )

                updated_profile, _unused, error = (
                    client.risk_profiles.update_risk_profile(
                        profile_id=profile_id_to_update,
                        profile_name=risk_profile_params.get("profile_name"),
                        profile_type=risk_profile_params.get("profile_type"),
                        risk_index=risk_profile_params.get("risk_index"),
                        status=risk_profile_params.get("status"),
                        exclude_certificates=risk_profile_params.get(
                            "exclude_certificates"
                        ),
                        certifications=risk_profile_params.get("certifications"),
                        poor_items_of_service=risk_profile_params.get(
                            "poor_items_of_service"
                        ),
                        admin_audit_logs=risk_profile_params.get("admin_audit_logs"),
                        data_breach=risk_profile_params.get("data_breach"),
                        source_ip_restrictions=risk_profile_params.get(
                            "source_ip_restrictions"
                        ),
                        mfa_support=risk_profile_params.get("mfa_support"),
                        ssl_pinned=risk_profile_params.get("ssl_pinned"),
                        http_security_headers=risk_profile_params.get(
                            "http_security_headers"
                        ),
                        evasive=risk_profile_params.get("evasive"),
                        dns_caa_policy=risk_profile_params.get("dns_caa_policy"),
                        weak_cipher_support=risk_profile_params.get(
                            "weak_cipher_support"
                        ),
                        password_strength=risk_profile_params.get("password_strength"),
                        ssl_cert_validity=risk_profile_params.get("ssl_cert_validity"),
                        vulnerability=risk_profile_params.get("vulnerability"),
                        malware_scanning_for_content=risk_profile_params.get(
                            "malware_scanning_for_content"
                        ),
                        file_sharing=risk_profile_params.get("file_sharing"),
                        ssl_cert_key_size=risk_profile_params.get("ssl_cert_key_size"),
                        vulnerable_to_heart_bleed=risk_profile_params.get(
                            "vulnerable_to_heart_bleed"
                        ),
                        vulnerable_to_log_jam=risk_profile_params.get(
                            "vulnerable_to_log_jam"
                        ),
                        vulnerable_to_poodle=risk_profile_params.get(
                            "vulnerable_to_poodle"
                        ),
                        vulnerability_disclosure=risk_profile_params.get(
                            "vulnerability_disclosure"
                        ),
                        support_for_waf=risk_profile_params.get("support_for_waf"),
                        remote_screen_sharing=risk_profile_params.get(
                            "remote_screen_sharing"
                        ),
                        sender_policy_framework=risk_profile_params.get(
                            "sender_policy_framework"
                        ),
                        domain_keys_identified_mail=risk_profile_params.get(
                            "domain_keys_identified_mail"
                        ),
                        domain_based_message_auth=risk_profile_params.get(
                            "domain_based_message_auth"
                        ),
                        data_encryption_in_transit=risk_profile_params.get(
                            "data_encryption_in_transit"
                        ),
                        custom_tags=risk_profile_params.get("custom_tags"),
                    )
                )

                if error:
                    module.fail_json(msg=f"Error updating profile: {to_native(error)}")
                module.exit_json(changed=True, data=updated_profile.as_dict())
            else:
                module.exit_json(changed=False, data=existing_profile)
        else:
            new_profile, _unused, error = client.risk_profiles.add_risk_profile(
                profile_name=risk_profile_params.get("profile_name"),
                risk_index=risk_profile_params.get("risk_index"),
                status=risk_profile_params.get("status"),
                exclude_certificates=risk_profile_params.get("exclude_certificates"),
                certifications=risk_profile_params.get("certifications"),
                poor_items_of_service=risk_profile_params.get("poor_items_of_service"),
                admin_audit_logs=risk_profile_params.get("admin_audit_logs"),
                data_breach=risk_profile_params.get("data_breach"),
                source_ip_restrictions=risk_profile_params.get(
                    "source_ip_restrictions"
                ),
                mfa_support=risk_profile_params.get("mfa_support"),
                ssl_pinned=risk_profile_params.get("ssl_pinned"),
                http_security_headers=risk_profile_params.get("http_security_headers"),
                evasive=risk_profile_params.get("evasive"),
                dns_caa_policy=risk_profile_params.get("dns_caa_policy"),
                weak_cipher_support=risk_profile_params.get("weak_cipher_support"),
                password_strength=risk_profile_params.get("password_strength"),
                ssl_cert_validity=risk_profile_params.get("ssl_cert_validity"),
                vulnerability=risk_profile_params.get("vulnerability"),
                malware_scanning_for_content=risk_profile_params.get(
                    "malware_scanning_for_content"
                ),
                file_sharing=risk_profile_params.get("file_sharing"),
                ssl_cert_key_size=risk_profile_params.get("ssl_cert_key_size"),
                vulnerable_to_heart_bleed=risk_profile_params.get(
                    "vulnerable_to_heart_bleed"
                ),
                vulnerable_to_log_jam=risk_profile_params.get("vulnerable_to_log_jam"),
                vulnerable_to_poodle=risk_profile_params.get("vulnerable_to_poodle"),
                vulnerability_disclosure=risk_profile_params.get(
                    "vulnerability_disclosure"
                ),
                support_for_waf=risk_profile_params.get("support_for_waf"),
                remote_screen_sharing=risk_profile_params.get("remote_screen_sharing"),
                sender_policy_framework=risk_profile_params.get(
                    "sender_policy_framework"
                ),
                domain_keys_identified_mail=risk_profile_params.get(
                    "domain_keys_identified_mail"
                ),
                domain_based_message_auth=risk_profile_params.get(
                    "domain_based_message_auth"
                ),
                data_encryption_in_transit=risk_profile_params.get(
                    "data_encryption_in_transit"
                ),
                custom_tags=risk_profile_params.get("custom_tags"),
            )
            if error:
                module.fail_json(msg=f"Error adding profile: {to_native(error)}")
            module.exit_json(changed=True, data=new_profile.as_dict())

    elif state == "absent":
        if existing_profile:
            profile_id_to_delete = existing_profile.get("id")
            if not profile_id_to_delete:
                module.fail_json(
                    msg="Cannot delete profile: ID is missing from the existing resource."
                )

            _unused, _unused, error = client.risk_profiles.delete_risk_profile(
                profile_id_to_delete
            )
            if error:
                module.fail_json(msg=f"Error deleting profile: {to_native(error)}")
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
            profile_name=dict(type="str", required=True),
            profile_type=dict(
                type="str", required=False, choices=["CLOUD_APPLICATIONS"]
            ),
            risk_index=dict(type="list", elements="int", required=False),
            status=dict(
                type="str",
                required=False,
                choices=["UN_SANCTIONED", "SANCTIONED", "ANY"],
            ),
            exclude_certificates=dict(type="int", required=False),
            certifications=dict(
                type="list",
                elements="str",
                required=False,
                choices=[
                    "CSA_STAR",
                    "ISO_27001",
                    "HIPAA",
                    "FISMA",
                    "FEDRAMP",
                    "SOC2",
                    "ISO_27018",
                    "PCI_DSS",
                    "ISO_27017",
                    "SOC1",
                    "SOC3",
                    "GDPR",
                    "CCPA",
                    "FERPA",
                    "COPPA",
                    "HITECH",
                    "EU_US_SWISS_PRIVACY_SHIELD",
                    "EU_US_PRIVACY_SHIELD_FRAMEWORK",
                    "CISP",
                    "AICPA",
                    "FIPS",
                    "SAFE_BIOPHARMA",
                    "ISAE_3000",
                    "SSAE_18",
                    "NIST",
                    "ISO_14001",
                    "SOC",
                    "TRUSTE",
                    "ISO_26262",
                    "ISO_20252",
                    "RGPD",
                    "ISO_20243",
                    "JIS_Q_27001",
                    "ISO_10002",
                    "JIS_Q_15001_2017",
                    "ISMAP",
                    "GAAP",
                ],
            ),
            poor_items_of_service=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            admin_audit_logs=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            data_breach=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            source_ip_restrictions=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            mfa_support=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            ssl_pinned=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            http_security_headers=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            evasive=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            dns_caa_policy=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            weak_cipher_support=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            password_strength=dict(
                type="str",
                required=False,
                no_log=False,
                choices=["ANY", "GOOD", "POOR", "UN_KNOWN"],
            ),
            ssl_cert_validity=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            vulnerability=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            malware_scanning_for_content=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            file_sharing=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            ssl_cert_key_size=dict(
                type="str",
                required=False,
                choices=[
                    "ANY",
                    "UN_KNOWN",
                    "BITS_2048",
                    "BITS_256",
                    "BITS_3072",
                    "BITS_384",
                    "BITS_4096",
                    "BITS_1024",
                    "BITS_8192",
                ],
            ),
            vulnerable_to_heart_bleed=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            vulnerable_to_log_jam=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            vulnerable_to_poodle=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            vulnerability_disclosure=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            support_for_waf=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            remote_screen_sharing=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            sender_policy_framework=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            domain_keys_identified_mail=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            domain_based_message_auth=dict(
                type="str", required=False, choices=["ANY", "YES", "NO", "UN_KNOWN"]
            ),
            data_encryption_in_transit=dict(
                type="list",
                elements="str",
                required=False,
                choices=[
                    "ANY",
                    "UN_KNOWN",
                    "TLSV1_0",
                    "TLSV1_1",
                    "TLSV1_2",
                    "TLSV1_3",
                    "SSLV2",
                    "SSLV3",
                ],
            ),
            custom_tags=dict(type="list", elements="dict", required=False),
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
