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
module: zia_atp_malware_policy
short_description: "Retrieves the malicious URLs added to the denylist"
description:
  - "Retrieves the malicious URLs added to the denylist in the (ATP) policy"
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
    description: "The unique identifier for the rule label."
    type: int
    required: false
  name:
    description: "The rule label name."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets all list of rule label
  zscaler.ziacloud.zia_rule_labels_info:
    provider: '{{ provider }}'

- name: Gets a list of rule label by name
  zscaler.ziacloud.zia_rule_labels_info:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
labels:
  description: A list of rule labels fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the rule label.
      returned: always
      type: int
      sample: 3687131
    name:
      description: The name of the rule label.
      returned: always
      type: str
      sample: "Example"
    description:
      description: A description of the rule label.
      returned: always
      type: str
      sample: "Example description"
    created_by:
      description: Information about the user who created the rule label.
      returned: always
      type: complex
      contains:
        id:
          description: The identifier of the user who created the rule label.
          returned: always
          type: int
          sample: 44772836
        name:
          description: The name of the user who created the rule label.
          returned: always
          type: str
          sample: "admin@44772833.zscalertwo.net"
    last_modified_by:
      description: Information about the user who last modified the rule label.
      returned: always
      type: complex
      contains:
        id:
          description: The identifier of the user who last modified the rule label.
          returned: always
          type: int
          sample: 44772836
        name:
          description: The name of the user who last modified the rule label.
          returned: always
          type: str
          sample: "admin@44772833.zscalertwo.net"
    last_modified_time:
      description: The Unix timestamp when the rule label was last modified.
      returned: always
      type: int
      sample: 1721347034
    referenced_rule_count:
      description: The number of rules that reference this label.
      returned: always
      type: int
      sample: 0
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    validate_iso3166_alpha2,
    convert_keys_to_snake_case
)

def core(module):
    state = module.params.get("state")
    if state != "present":
        module.fail_json(msg="Only 'present' is supported for this module.")

    client = ZIAClientHelper(module)

    # Define the supported atp fields
    params = [
        "risk_tolerance", "risk_tolerance_capture",
        "cmd_ctl_server_blocked", "cmd_ctl_server_capture",
        "cmd_ctl_traffic_blocked", "cmd_ctl_traffic_capture",
        "malware_sites_blocked", "malware_sites_capture",
        "active_x_blocked", "active_x_capture",
        "browser_exploits_blocked", "browser_exploits_capture",
        "file_format_vunerabilites_blocked", "file_format_vunerabilites_capture",
        "known_phishing_sites_blocked", "known_phishing_sites_capture",
        "suspected_phishing_sites_blocked", "suspected_phishing_sites_capture",
        "suspect_adware_spyware_sites_blocked", "suspect_adware_spyware_sites_capture",
        "webspam_blocked", "webspam_capture",
        "irc_tunnelling_blocked", "irc_tunnelling_capture",
        "anonymizer_blocked", "anonymizer_capture",
        "cookie_stealing_blocked", "cookie_stealing_pcap_enabled",
        "potential_malicious_requests_blocked", "potential_malicious_requests_capture",
        "blocked_countries", "block_countries_capture",
        "bit_torrent_blocked", "bit_torrent_capture",
        "tor_blocked", "tor_capture",
        "google_talk_blocked", "google_talk_capture",
        "ssh_tunnelling_blocked", "ssh_tunnelling_capture",
        "crypto_mining_blocked", "crypto_mining_capture",
        "ad_spyware_sites_blocked", "ad_spyware_sites_capture",
        "dga_domains_blocked", "dga_domains_capture",
        "alert_for_unknown_or_suspicious_c2_traffic", "malicious_urls_capture"
    ]

    settings_data = {k: module.params.get(k) for k in params if module.params.get(k) is not None}

    # Validate and format country codes
    source_countries = settings_data.get("blocked_countries")
    if source_countries:
        validated_source_countries = []
        for country_code in source_countries:
            if validate_iso3166_alpha2(country_code):
                validated_source_countries.append(f"COUNTRY_{country_code}")
            else:
                module.fail_json(
                    msg=f"Invalid source country code '{country_code}'. Must be ISO3166 Alpha2."
                )
        settings_data["blocked_countries"] = validated_source_countries

    current_settings, _, error = client.atp_policy.get_atp_settings()
    if error:
        module.fail_json(msg=f"Error fetching atp advanced settings: {to_native(error)}")

    # Prefer _raw_config if available, fallback to as_dict()
    if hasattr(current_settings, "_raw_config") and current_settings._raw_config:
        raw_response = current_settings._raw_config
    else:
        raw_response = current_settings.as_dict()

    module.warn(f"🧪 Raw keys from API: {list(raw_response.keys())}")
    current_dict = convert_keys_to_snake_case(raw_response)

    drift = any(current_dict.get(k) != settings_data.get(k) for k in settings_data)

    module.warn(f"📦 Raw SDK response: {current_settings}")
    module.warn(f"🐍 Snake_case converted: {current_dict}")
    module.warn(f"🔍 Current settings: {current_dict}")
    module.warn(f"📅 Desired settings: {settings_data}")
    module.warn(f"🧠 Drift detected: {drift}")

    if module.check_mode:
        module.exit_json(changed=drift)

    if drift:
        for k, v in settings_data.items():
            setattr(current_settings, k, v)

        updated, _, error = client.atp_policy.update_atp_settings(current_settings)
        if error:
            module.fail_json(msg=f"Error updating malware settings: {to_native(error)}")

        module.exit_json(changed=True, malware_settings=updated.as_dict())

    module.exit_json(changed=False, malware_settings=current_dict)

def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(dict(
        risk_tolerance=dict(type="int", required=False),
        risk_tolerance_capture=dict(type="bool", required=False),
        cmd_ctl_server_blocked=dict(type="bool", required=False),
        cmd_ctl_server_capture=dict(type="bool", required=False),
        cmd_ctl_traffic_blocked=dict(type="bool", required=False),
        cmd_ctl_traffic_capture=dict(type="bool", required=False),
        malware_sites_blocked=dict(type="bool", required=False),
        malware_sites_capture=dict(type="bool", required=False),
        active_x_blocked=dict(type="bool", required=False),
        active_x_capture=dict(type="bool", required=False),
        browser_exploits_blocked=dict(type="bool", required=False),
        browser_exploits_capture=dict(type="bool", required=False),
        file_format_vunerabilites_blocked=dict(type="bool", required=False),
        file_format_vunerabilites_capture=dict(type="bool", required=False),
        known_phishing_sites_blocked=dict(type="bool", required=False),
        known_phishing_sites_capture=dict(type="bool", required=False),
        suspected_phishing_sites_blocked=dict(type="bool", required=False),
        suspected_phishing_sites_capture=dict(type="bool", required=False),
        suspect_adware_spyware_sites_blocked=dict(type="bool", required=False),
        suspect_adware_spyware_sites_capture=dict(type="bool", required=False),
        webspam_blocked=dict(type="bool", required=False),
        webspam_capture=dict(type="bool", required=False),
        irc_tunnelling_blocked=dict(type="bool", required=False),
        irc_tunnelling_capture=dict(type="bool", required=False),
        anonymizer_blocked=dict(type="bool", required=False),
        anonymizer_capture=dict(type="bool", required=False),
        cookie_stealing_blocked=dict(type="bool", required=False),
        cookie_stealing_pcap_enabled=dict(type="bool", required=False),
        potential_malicious_requests_blocked=dict(type="bool", required=False),
        potential_malicious_requests_capture=dict(type="bool", required=False),
        blocked_countries=dict(type="list", elements="str", required=False),
        block_countries_capture=dict(type="bool", required=False),
        bit_torrent_blocked=dict(type="bool", required=False),
        bit_torrent_capture=dict(type="bool", required=False),
        tor_blocked=dict(type="bool", required=False),
        tor_capture=dict(type="bool", required=False),
        google_talk_blocked=dict(type="bool", required=False),
        google_talk_capture=dict(type="bool", required=False),
        ssh_tunnelling_blocked=dict(type="bool", required=False),
        ssh_tunnelling_capture=dict(type="bool", required=False),
        crypto_mining_blocked=dict(type="bool", required=False),
        crypto_mining_capture=dict(type="bool", required=False),
        ad_spyware_sites_blocked=dict(type="bool", required=False),
        ad_spyware_sites_capture=dict(type="bool", required=False),
        dga_domains_blocked=dict(type="bool", required=False),
        dga_domains_capture=dict(type="bool", required=False),
        alert_for_unknown_or_suspicious_c2_traffic=dict(type="bool", required=False),
        malicious_urls_capture=dict(type="bool", required=False),
        state=dict(type="str", choices=["present"], default="present")
    ))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()