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
module: zia_atp_settings
short_description: "Updates the advanced threat configuration settings"
description:
  - "Updates the advanced threat configuration settings"
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
  - zscaler.ziacloud.fragments.modified_state

options:
  risk_tolerance:
    description:
      - The Page Risk tolerance index set between 0 and 100 (100 being the highest risk).
      - Users are blocked from accessing web pages with higher Page Risk than the specified value.
    type: int
    required: false
  risk_tolerance_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for suspicious web pages
    required: false
    type: bool
  cmd_ctl_server_blocked:
    description: Indicates whether connections to known Command & Control (C2) Servers are allowed or blocked
    required: false
    type: bool
  cmd_ctl_server_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for connections to known C2 servers
    required: false
    type: bool
  cmd_ctl_traffic_blocked:
    description: Indicates whether botnets are allowed or blocked from sending or receiving commands to unknown servers
    required: false
    type: bool
  cmd_ctl_traffic_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for botnets
    required: false
    type: bool
  malware_sites_blocked:
    description: Indicates whether known malicious sites and content are allowed or blocked
    required: false
    type: bool
  malware_sites_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for malicious sites
    required: false
    type: bool
  active_x_blocked:
    description: Indicates whether sites are allowed or blocked from accessing vulnerable ActiveX controls that are known to have been exploited.
    required: false
    type: bool
  active_x_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for ActiveX controls
    required: false
    type: bool
  browser_exploits_blocked:
    description: Indicates whether known web browser vulnerabilities prone to exploitation are allowed or blocked.
    required: false
    type: bool
  browser_exploits_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for browser exploits
    required: false
    type: bool
  file_format_vunerabilites_blocked:
    description:
      - Indicates whether known file format vulnerabilities and suspicious or malicious content in
      - Microsoft Office or PDF documents are allowed or blocked
    required: false
    type: bool
  file_format_vunerabilites_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for file format vulnerabilities
    required: false
    type: bool
  known_phishing_sites_blocked:
    description: Indicates whether known phishing sites are allowed or blocked
    required: false
    type: bool
  known_phishing_sites_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for known phishing sites
    required: false
    type: bool
  suspected_phishing_sites_blocked:
    description:
      - Indicates whether to allow or block suspected phishing sites identified through heuristic detection.
      - The Zscaler service can inspect the content of a website for indications that it might be a phishing site.
    required: false
    type: bool
  suspected_phishing_sites_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for suspected phishing sites
    required: false
    type: bool
  suspect_adware_spyware_sites_blocked:
    description:
      - Indicates whether to allow or block any detections of communication and callback traffic associated
      - with spyware agents and data transmission
    required: false
    type: bool
  suspect_adware_spyware_sites_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for suspected adware and spyware sites
    required: false
    type: bool
  webspam_blocked:
    description:
      - Indicates whether to allow or block web pages that pretend to contain useful information,
      - To get higher ranking in search engine results or drive traffic to phishing, adware, or spyware distribution sites.
    required: false
    type: bool
  webspam_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for web spam
    required: false
    type: bool
  irc_tunnelling_blocked:
    description: Indicates whether to allow or block IRC traffic being tunneled over HTTP and HTTPS
    required: false
    type: bool
  irc_tunnelling_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for IRC tunnels
    required: false
    type: bool
  anonymizer_blocked:
    description:
      - Indicates whether to allow or block applications and methods used to obscure the destination
      - and the content accessed by the user, therefore blocking traffic to anonymizing web proxies.
    required: false
    type: bool
  anonymizer_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for anonymizers
    required: false
    type: bool
  cookie_stealing_blocked:
    description:
      - Indicates whether to allow or block third-party websites that gather cookie information
      - which can be used to personally identify users, track internet activity, or steal a user's session or sensitive information.
    required: false
    type: bool
  cookie_stealing_pcap_enabled:
    description: Indicates whether packet capture (PCAP) is enabled or not for cookie stealing
    required: false
    type: bool
  potential_malicious_requests_blocked:
    description: Indicates whether to allow or block this type of cross-site scripting (XSS)
    required: false
    type: bool
  potential_malicious_requests_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for (XSS) attacks
    required: false
    type: bool
  blocked_countries:
    description:
      - Whether to allow or block requests to websites located in specific countries.
      - Provide a ISO3166 Alpha2 code. Visit the following site for reference U(https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)
    type: list
    elements: str
    required: false
  block_countries_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for blocked countries
    required: false
    type: bool
  bit_torrent_blocked:
    description:
      - Indicates whether to allow or block the usage of BitTorrent, a popular
      - P2P file sharing application that supports content download with encryption.
    required: false
    type: bool
  bit_torrent_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for BitTorrent
    required: false
    type: bool
  tor_blocked:
    description: Indicates whether to allow or block the usage of Tor, a popular P2P anonymizer protocol with support for encryption.
    required: false
    type: bool
  tor_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for Tor
    required: false
    type: bool
  google_talk_blocked:
    description: Indicates whether to allow or block access to Google Hangouts, a popular P2P VoIP application.
    required: false
    type: bool
  google_talk_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for Google
    required: false
    type: bool
  ssh_tunnelling_blocked:
    description: Indicates whether to allow or block SSH traffic being tunneled over HTTP and HTTPS
    required: false
    type: bool
  ssh_tunnelling_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for SSH tunnels
    required: false
    type: bool
  crypto_mining_blocked:
    description:
      - Indicates whether to allow or block cryptocurrency mining network traffic and scripts
      - Which can negatively impact endpoint device performance and potentially lead to a misuse of company resources.
    required: false
    type: bool
  crypto_mining_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for cryptomining
    required: false
    type: bool
  ad_spyware_sites_blocked:
    description:
      - Indicates whether to allow or block websites known to contain adware or
      - spyware that displays malicious advertisements that can collect users' information without their knowledge
    required: false
    type: bool
  ad_spyware_sites_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for adware and spyware sites
    required: false
    type: bool
  dga_domains_blocked:
    description: Indicates whether to allow or block domains that are suspected to be generated using domain generation algorithms (DGA)
    required: false
    type: bool
  dga_domains_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for DGA domains
    required: false
    type: bool
  alert_for_unknown_or_suspicious_c2_traffic:
    description: Indicates whether to send alerts upon detecting unknown or suspicious C2 traffic
    required: false
    type: bool
  malicious_urls_capture:
    description: Indicates whether packet capture (PCAP) is enabled or not for malicious URLs
    required: false
    type: bool
"""

EXAMPLES = r"""
- name: Updates the advanced threat configuration settings
  zscaler.ziacloud.zia_atp_settings:
    provider: '{{ provider }}'
    risk_tolerance: 50
    risk_tolerance_capture: false
    cmd_ctl_server_blocked: true
    cmd_ctl_server_capture: false
    cmd_ctl_traffic_blocked: true
    cmd_ctl_traffic_capture: false
    malware_sites_blocked: true
    malware_sites_capture: false
    active_x_blocked: true
    active_x_capture: false
    browser_exploits_blocked: true
    browser_exploits_capture: false
    file_format_vunerabilites_blocked: true
    file_format_vunerabilites_capture: false
    known_phishing_sites_blocked: true
    known_phishing_sites_capture: false
    suspected_phishing_sites_blocked: true
    suspected_phishing_sites_capture: false
    suspect_adware_spyware_sites_blocked: true
    suspect_adware_spyware_sites_capture: false
    webspam_blocked: true
    webspam_capture: false
    irc_tunnelling_blocked: true
    irc_tunnelling_capture: false
    anonymizer_blocked: true
    anonymizer_capture: false
    cookie_stealing_blocked: true
    cookie_stealing_pcap_enabled: false
    potential_malicious_requests_blocked: true
    potential_malicious_requests_capture: false
    blocked_countries:
      - BR
      - CA
      - CN
      - RU
      - US
    block_countries_capture: false
    bit_torrent_blocked: true
    bit_torrent_capture: false
    tor_blocked: true
    tor_capture: false
    google_talk_blocked: true
    google_talk_capture: false
    ssh_tunnelling_blocked: true
    ssh_tunnelling_capture: false
    crypto_mining_blocked: true
    crypto_mining_capture: false
"""

RETURN = r"""
#  Advanced Threat Protection Settings.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    validate_iso3166_alpha2,
    convert_keys_to_snake_case,
)


def core(module):
    state = module.params.get("state")
    if state != "present":
        module.fail_json(msg="Only 'present' is supported for this module.")

    client = ZIAClientHelper(module)

    # Define the supported atp fields
    params = [
        "risk_tolerance",
        "risk_tolerance_capture",
        "cmd_ctl_server_blocked",
        "cmd_ctl_server_capture",
        "cmd_ctl_traffic_blocked",
        "cmd_ctl_traffic_capture",
        "malware_sites_blocked",
        "malware_sites_capture",
        "active_x_blocked",
        "active_x_capture",
        "browser_exploits_blocked",
        "browser_exploits_capture",
        "file_format_vunerabilites_blocked",
        "file_format_vunerabilites_capture",
        "known_phishing_sites_blocked",
        "known_phishing_sites_capture",
        "suspected_phishing_sites_blocked",
        "suspected_phishing_sites_capture",
        "suspect_adware_spyware_sites_blocked",
        "suspect_adware_spyware_sites_capture",
        "webspam_blocked",
        "webspam_capture",
        "irc_tunnelling_blocked",
        "irc_tunnelling_capture",
        "anonymizer_blocked",
        "anonymizer_capture",
        "cookie_stealing_blocked",
        "cookie_stealing_pcap_enabled",
        "potential_malicious_requests_blocked",
        "potential_malicious_requests_capture",
        "blocked_countries",
        "block_countries_capture",
        "bit_torrent_blocked",
        "bit_torrent_capture",
        "tor_blocked",
        "tor_capture",
        "google_talk_blocked",
        "google_talk_capture",
        "ssh_tunnelling_blocked",
        "ssh_tunnelling_capture",
        "crypto_mining_blocked",
        "crypto_mining_capture",
        "ad_spyware_sites_blocked",
        "ad_spyware_sites_capture",
        "dga_domains_blocked",
        "dga_domains_capture",
        "alert_for_unknown_or_suspicious_c2_traffic",
        "malicious_urls_capture",
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
                module.fail_json(msg=f"Invalid source country code '{country_code}'. Must be ISO3166 Alpha2.")
        settings_data["blocked_countries"] = validated_source_countries

    current_settings, _unused, error = client.atp_policy.get_atp_settings()
    if error:
        module.fail_json(msg=f"Error fetching atp advanced settings: {to_native(error)}")

    # Prefer _raw_config if available, fallback to as_dict()
    if hasattr(current_settings, "_raw_config") and current_settings._raw_config:
        raw_response = current_settings._raw_config
    else:
        raw_response = current_settings.as_dict()

    # module.warn(f"🧪 Raw keys from API: {list(raw_response.keys())}")
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

        updated, _unused, error = client.atp_policy.update_atp_settings(**current_settings.as_dict())

        if error:
            module.fail_json(msg=f"Error updating malware settings: {to_native(error)}")

        module.exit_json(changed=True, malware_settings=updated.as_dict())

    module.exit_json(changed=False, malware_settings=current_dict)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
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
            state=dict(type="str", choices=["present"], default="present"),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
