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
module: zia_atp_settings_info
short_description: "Retrieves the advanced threat configuration settings"
description:
  - "Retrieves the advanced threat configuration settings"
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
- name: Retrieves the advanced threat configuration settings
  zscaler.ziacloud.zia_atp_settings_info:
    provider: '{{ provider }}'
"""

RETURN = r"""
atp:
  description: A dictionary of Advanced Threat Protection settings.
  returned: always
  type: dict
  contains:
    active_x_blocked:
      description: Indicates whether sites are allowed or blocked from accessing vulnerable ActiveX controls that are known to have been exploited.
      type: bool
      returned: always
    active_x_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for ActiveX controls
      type: bool
      returned: always
    ad_spyware_sites_blocked:
      description:
        - Indicates whether to allow or block websites known to contain adware or spyware that displays malicious
        - advertisements that can collect users' information without their knowledge
      type: bool
      returned: always
    ad_spyware_sites_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for adware and spyware sites
      type: bool
      returned: always
    alert_for_unknown_or_suspicious_c2_traffic:
      description: Indicates whether to send alerts upon detecting unknown or suspicious C2 traffic
      type: bool
      returned: always
    anonymizer_blocked:
      description:
        - Indicates whether to allow or block applications and methods used to obscure the
        - destination and the content accessed by the user, therefore blocking traffic to anonymizing web proxies.
      type: bool
      returned: always
    anonymizer_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for anonymizers
      type: bool
      returned: always
    bit_torrent_blocked:
      description:
        - Indicates whether to allow or block the usage of BitTorrent, a popular P2P file
        - sharing application that supports content download with encryption.
      type: bool
      returned: always
    bit_torrent_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for BitTorrent
      type: bool
      returned: always
    block_countries_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for blocked countries
      type: bool
      returned: always
    blocked_countries:
      description: Whether to allow or block requests to websites located in specific countries. Provide a ISO3166 Alpha2 code.
      type: list
      elements: str
      returned: always
    browser_exploits_blocked:
      description: Indicates whether known web browser vulnerabilities prone to exploitation are allowed or blocked.
      type: bool
      returned: always
    browser_exploits_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for browser exploits
      type: bool
      returned: always
    cmd_ctl_server_blocked:
      description: Indicates whether connections to known Command & Control (C2) Servers are allowed or blocked
      type: bool
      returned: always
    cmd_ctl_server_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for connections to known C2 servers
      type: bool
      returned: always
    cmd_ctl_traffic_blocked:
      description: Indicates whether botnets are allowed or blocked from sending or receiving commands to unknown servers
      type: bool
      returned: always
    cmd_ctl_traffic_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for botnets
      type: bool
      returned: always
    cookie_stealing_blocked:
      description:
        - Indicates whether to allow or block third-party websites that gather cookie information,
        - which can be used to personally identify users, track internet activity, or steal a user's session or sensitive information.
      type: bool
      returned: always
    cookie_stealing_pcap_enabled:
      description: Indicates whether packet capture (PCAP) is enabled or not for cookie stealing
      type: bool
      returned: always
    crypto_mining_blocked:
      description:
        - Indicates whether to allow or block cryptocurrency mining network traffic and scripts
        - which can negatively impact endpoint device performance and potentially lead to a misuse of company resources.
      type: bool
      returned: always
    crypto_mining_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for cryptomining
      type: bool
      returned: always
    dga_domains_blocked:
      description: Indicates whether to allow or block domains that are suspected to be generated using domain generation algorithms (DGA)
      type: bool
      returned: always
    dga_domains_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for DGA domains
      type: bool
      returned: always
    file_format_vunerabilites_blocked:
      description:
        - Indicates whether known file format vulnerabilities and suspicious or malicious content in
        - Microsoft Office or PDF documents are allowed or blocked
      type: bool
      returned: always
    file_format_vunerabilites_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for file format vulnerabilities
      type: bool
      returned: always
    google_talk_blocked:
      description: Indicates whether to allow or block access to Google Hangouts, a popular P2P VoIP application.
      type: bool
      returned: always
    google_talk_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for Google
      type: bool
      returned: always
    irc_tunnelling_blocked:
      description: Indicates whether to allow or block IRC traffic being tunneled over HTTP and HTTPS
      type: bool
      returned: always
    irc_tunnelling_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for IRC tunnels
      type: bool
      returned: always
    known_phishing_sites_blocked:
      description: Indicates whether known phishing sites are allowed or blocked
      type: bool
      returned: always
    known_phishing_sites_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for known phishing sites
      type: bool
      returned: always
    malicious_urls_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for malicious URLs
      type: bool
      returned: always
    malware_sites_blocked:
      description: Indicates whether known malicious sites and content are allowed or blocked
      type: bool
      returned: always
    malware_sites_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for malicious sites
      type: bool
      returned: always
    potential_malicious_requests_blocked:
      description: Indicates whether to allow or block this type of cross-site scripting (XSS)
      type: bool
      returned: always
    potential_malicious_requests_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for (XSS) attacks
      type: bool
      returned: always
    risk_tolerance:
      description:
        - The Page Risk tolerance index set between 0 and 100 (100 being the highest risk).
        - Users are blocked from accessing web pages with higher Page Risk than the specified value.
      type: int
      returned: always
    risk_tolerance_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for suspicious web pages
      type: bool
      returned: always
    ssh_tunnelling_blocked:
      description: Indicates whether to allow or block SSH traffic being tunneled over HTTP and HTTPS
      type: bool
      returned: always
    ssh_tunnelling_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for SSH tunnels
      type: bool
      returned: always
    suspect_adware_spyware_sites_blocked:
      description:
        - Indicates whether to allow or block any detections of communication and callback traffic
        - associated with spyware agents and data transmission
      type: bool
      returned: always
    suspect_adware_spyware_sites_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for suspected adware and spyware sites
      type: bool
      returned: always
    suspected_phishing_sites_blocked:
      description:
        - Indicates whether to allow or block suspected phishing sites identified through heuristic detection.
        - The Zscaler service can inspect the content of a website for indications that it might be a phishing site.
      type: bool
      returned: always
    suspected_phishing_sites_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for suspected phishing sites
      type: bool
      returned: always
    tor_blocked:
      description: Indicates whether to allow or block the usage of Tor, a popular P2P anonymizer protocol with support for encryption.
      type: bool
      returned: always
    tor_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for Tor
      type: bool
      returned: always
    webspam_blocked:
      description:
        - Indicates whether to allow or block web pages that pretend to contain useful information,
        - to get higher ranking in search engine results or drive traffic to phishing, adware, or spyware distribution sites.
      type: bool
      returned: always
    webspam_capture:
      description: Indicates whether packet capture (PCAP) is enabled or not for web spam
      type: bool
      returned: always
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    client = ZIAClientHelper(module)

    atp, _unused, error = client.atp_policy.get_atp_settings()
    if error:
        module.fail_json(msg=f"Error fetching atp advanced settings: {to_native(error)}")

    module.exit_json(changed=False, atp=atp.as_dict())


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
