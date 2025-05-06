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
module: zia_advanced_settings_info
short_description: Gets information about the advanced settings configured in the ZIA Admin Portal
description: Gets information about the advanced settings configured in the ZIA Admin Portal
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
- name: Gets information about the advanced settings
  zscaler.ziacloud.zia_advanced_settings_info:
    provider: '{{ provider }}'
"""

RETURN = r"""
advanced_settings:
  description: Advanced settings configured in the ZIA Admin Portal.
  returned: always
  type: dict
  contains:
    auth_bypass_apps:
      description: Cloud applications that are exempted from cookie authentication
      type: list
      elements: str
      returned: always
    auth_bypass_url_categories:
      description: URL categories that are exempted from cookie authentication
      type: list
      elements: str
      returned: always
    auth_bypass_urls:
      description: Custom URLs that are exempted from cookie authentication for users
      type: list
      elements: str
      returned: always
    basic_bypass_apps:
      description: Cloud applications that are exempted from Basic authentication
      type: list
      elements: str
      returned: always
    basic_bypass_url_categories:
      description: URL categories that are exempted from Basic authentication
      type: list
      elements: str
      returned: always
    block_domain_fronting_apps:
      description: Applications that are exempted from domain fronting
      type: list
      elements: str
      returned: always
    digest_auth_bypass_apps:
      description: Cloud applications that are exempted from Digest authentication
      type: list
      elements: str
      returned: always
    digest_auth_bypass_url_categories:
      description: URL categories that are exempted from Digest authentication
      type: list
      elements: str
      returned: always
    digest_auth_bypass_urls:
      description: Custom URLs that are exempted from Digest authentication
      type: list
      elements: str
      returned: always
    dns_resolution_on_transparent_proxy_apps:
      description: Cloud applications to which DNS optimization on transparent proxy mode applies
      type: list
      elements: str
      returned: always
    dns_resolution_on_transparent_proxy_exempt_apps:
      description: Cloud applications that are excluded from DNS optimization on transparent proxy mode
      type: list
      elements: str
      returned: always
    dns_resolution_on_transparent_proxy_exempt_url_categories:
      description: URL categories that are excluded from DNS optimization on transparent proxy mode
      type: list
      elements: str
      returned: always
    dns_resolution_on_transparent_proxy_exempt_urls:
      description: URLs that are excluded from DNS optimization on transparent proxy mode
      type: list
      elements: str
      returned: always
    dns_resolution_on_transparent_proxy_ipv6_apps:
      description: Cloud applications to which DNS optimization for IPv6 addresses on transparent proxy mode applies
      type: list
      elements: str
      returned: always
    dns_resolution_on_transparent_proxy_ipv6_exempt_apps:
      description: Cloud applications that are excluded from DNS optimization for IPv6 addresses on transparent proxy mode
      type: list
      elements: str
      returned: always
    dns_resolution_on_transparent_proxy_ipv6_exempt_url_categories:
      description: IPv6 URL categories that are excluded from DNS optimization on transparent proxy mode
      type: list
      elements: str
      returned: always
    dns_resolution_on_transparent_proxy_ipv6_url_categories:
      description: IPv6 URL categories to which DNS optimization on transparent proxy mode applies
      type: list
      elements: str
      returned: always
    dns_resolution_on_transparent_proxy_url_categories:
      description: URL categories to which DNS optimization on transparent proxy mode applies
      type: list
      elements: str
      returned: always
    dns_resolution_on_transparent_proxy_urls:
      description: URLs to which DNS optimization on transparent proxy mode applies
      type: list
      elements: str
      returned: always
    domain_fronting_bypass_url_categories:
      description: URL categories that are exempted from domain fronting
      type: list
      elements: str
      returned: always
    http_range_header_remove_url_categories:
      description: URL categories for which HTTP range headers must be removed
      type: list
      elements: str
      returned: always
    kerberos_bypass_apps:
      description: Cloud applications that are exempted from Kerberos authentication
      type: list
      elements: str
      returned: always
    kerberos_bypass_url_categories:
      description: URL categories that are exempted from Kerberos authentication
      type: list
      elements: str
      returned: always
    kerberos_bypass_urls:
      description: Custom URLs that are exempted from Kerberos authentication
      type: list
      elements: str
      returned: always
    prefer_sni_over_conn_host_apps:
      description: Applications that are exempted from the preferSniOverConnHost setting
      type: list
      elements: str
      returned: always
    sni_dns_optimization_bypass_url_categories:
      description: URL categories that are excluded from the preferSniOverConnHost setting
      type: list
      elements: str
      returned: always
    enable_office365:
      description: Indicates whether Microsoft Office 365 One Click Configuration is enabled
      type: bool
      returned: always
    log_internal_ip:
      description: Indicates whether to log internal IP addresses in XFF headers
      type: bool
      returned: always
    enforce_surrogate_ip_for_windows_app:
      description: Enforce Surrogate IP authentication for Windows app traffic
      type: bool
      returned: always
    track_http_tunnel_on_http_ports:
      description: Apply policies on tunneled HTTP traffic using CONNECT on port 80
      type: bool
      returned: always
    block_http_tunnel_on_non_http_ports:
      description: Block HTTP CONNECT method requests to non-standard ports
      type: bool
      returned: always
    zscaler_client_connector1_and_pac_road_warrior_in_firewall:
      description: Apply firewall rules for PAC/Z-Tunnel 1.0 traffic
      type: bool
      returned: always
    cascade_url_filtering:
      description: Apply URL Filtering policy even when Cloud App Control allows transaction
      type: bool
      returned: always
    enable_policy_for_unauthenticated_traffic:
      description: Apply policies for unauthenticated traffic
      type: bool
      returned: always
    block_non_compliant_http_request_on_http_ports:
      description: Block non-compliant HTTP protocol requests
      type: bool
      returned: always
    enable_admin_rank_access:
      description: Enable admin rank-based policy control
      type: bool
      returned: always
    ui_session_timeout:
      description: Admin Portal login session timeout (seconds)
      type: int
      returned: always
    http2_nonbrowser_traffic_enabled:
      description: Use HTTP/2 as the default web protocol for non-browser apps
      type: bool
      returned: always
    ecs_for_all_enabled:
      description: Include ECS option in all DNS queries for all users/locations
      type: bool
      returned: always
    dynamic_user_risk_enabled:
      description: Dynamically update user risk score in real time
      type: bool
      returned: always
    block_connect_host_sni_mismatch:
      description: Block mismatches between CONNECT host and SNI in TLS
      type: bool
      returned: always
    prefer_sni_over_conn_host:
      description: Use TLS SNI instead of CONNECT host for DNS resolution
      type: bool
      returned: always
    sipa_xff_header_enabled:
      description: Insert XFF header to traffic forwarded from ZIA to ZPA
      type: bool
      returned: always
    block_non_http_on_http_port_enabled:
      description: Block non-HTTP traffic on ports 80 and 443
      type: bool
      returned: always
    enable_evaluate_policy_on_global_ssl_bypass:
      description: Enable policy evaluation on globally bypassed SSL traffic
      type: bool
      returned: always
    enable_ipv6_dns_optimization_on_all_transparent_proxy:
      description: Enable DNS optimization for all IPv6 transparent proxy traffic
      type: bool
      returned: always
    enable_ipv6_dns_resolution_on_transparent_proxy:
      description: Enable IPv6 DNS optimization for Z-Tunnel 2.0/transparent proxy
      type: bool
      returned: always
    block_domain_fronting_on_host_header:
      description: Block domain fronting based on FQDN mismatch
      type: bool
      returned: always
    enable_dns_resolution_on_transparent_proxy:
      description: Enable DNS optimization for transparent proxy traffic
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

    settings, _unused, error = client.advanced_settings.get_advanced_settings()
    if error:
        module.fail_json(msg=f"Error fetching advanced settings: {to_native(error)}")

    module.exit_json(changed=False, advanced_settings=settings.as_dict())


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
