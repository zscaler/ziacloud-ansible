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
module: zia_cloud_app_control_rules_info
short_description: Gets the list of cloud application rules by the type of rule..
description: Gets the list of cloud application rules by the type of rule..
author:
  - William Guilherme (@willguibr)
version_added: "1.3.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  id:
    description:
        - The universally unique identifier (UUID) for the browser isolation profile.
    type: str
    required: false
  name:
    description:
        - Name of the cloud application control rule.
    required: false
    type: str
  rule_type:
    description:
        - The rule type selected from the available options.
    required: true
    type: str
    choices:
      - SOCIAL_NETWORKING
      - STREAMING_MEDIA
      - WEBMAIL
      - INSTANT_MESSAGING
      - BUSINESS_PRODUCTIVITY
      - ENTERPRISE_COLLABORATION
      - SALES_AND_MARKETING
      - SYSTEM_AND_DEVELOPMENT
      - CONSUMER
      - HOSTING_PROVIDER
      - IT_SERVICES
      - FILE_SHARE
      - DNS_OVER_HTTPS
      - HUMAN_RESOURCES
      - LEGAL
      - HEALTH_CARE
      - FINANCE
      - CUSTOM_CAPP
      - AI_ML
"""

EXAMPLES = r"""
- name: Gather Information Details of a cloud application control rule by Name
  zscaler.ziacloud.zia_cloud_app_control_rules_info:
    provider: '{{ provider }}'
    name: "Webmail Rule-1"
    rule_type: "WEBMAIL"
"""

RETURN = r"""
rules:
    description: A list of cloud application control rules that match the specified criteria.
    returned: always
    type: list
    elements: dict
    sample: [
        {
            "access_control": "READ_WRITE",
            "actions": [
                "ALLOW_WEBMAIL_VIEW",
                "ALLOW_WEBMAIL_ATTACHMENT_SEND"
            ],
            "applications": [
                "GOOGLE_WEBMAIL",
                "YAHOO_WEBMAIL",
                "WINDOWS_LIVE_HOTMAIL"
            ],
            "browser_eun_template_id": 0,
            "cascading_enabled": false,
            "enforce_time_validity": false,
            "eun_enabled": false,
            "eun_template_id": 0,
            "id": 552617,
            "name": "Webmail Rule-1",
            "order": 2,
            "predefined": false,
            "rank": 7,
            "state": "DISABLED",
            "type": "WEBMAIL"
        }
    ]
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper

def normalize_settings(data):
    """Remove keys with None values and normalize unordered lists for comparison."""
    if isinstance(data, dict):
        return {
            k: normalize_settings(v)
            for k, v in data.items()
            if v is not None
        }

    elif isinstance(data, list):
        try:
            return sorted([normalize_settings(v) for v in data if v is not None])
        except Exception:
            return [normalize_settings(v) for v in data if v is not None]

    return data

def core(module):
    client = ZIAClientHelper(module)

    current_settings, _, error = client.advanced_settings.get_advanced_settings()
    if error:
        module.fail_json(msg=f"Error fetching advanced settings: {to_native(error)}")

    # Construct desired state from module params
    desired_raw = {
        k: module.params.get(k) for k in module.params if k not in ["state"]
    }
    desired_clean = normalize_settings(desired_raw)
    current_clean = normalize_settings(current_settings.as_dict())

    # Debug logging
    module.warn(f"🔍 Current Settings: {current_clean}")
    module.warn(f"📥 Desired Settings: {desired_clean}")

    if module.check_mode:
        module.exit_json(changed=desired_clean != current_clean)

    if desired_clean != current_clean:
        # Merge into existing object
        for k, v in desired_clean.items():
            setattr(current_settings, k, v)

        module.warn("📦 Payload Update for SDK: {}".format(current_settings.request_format()))
        updated, _, error = client.advanced_settings.update_advanced_settings(current_settings)
        if error:
            module.fail_json(msg=f"Error updating advanced settings: {to_native(error)}")
        module.exit_json(changed=True, advanced_settings=updated.as_dict())

    module.exit_json(changed=False, advanced_settings=current_settings.as_dict())


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            auth_bypass_urls=dict(type="list", elements="str", required=False),
            kerberos_bypass_urls=dict(type="list", elements="str", required=False),
            digest_auth_bypass_urls=dict(type="list", elements="str", required=False),
            dns_resolution_on_transparent_proxy_exempt_urls=dict(type="list", elements="str", required=False),
            dns_resolution_on_transparent_proxy_urls=dict(type="list", elements="str", required=False),

            enable_dns_resolution_on_transparent_proxy=dict(type="bool", required=False),
            enable_ipv6_dns_resolution_on_transparent_proxy=dict(type="bool", required=False),
            enable_ipv6_dns_optimization_on_all_transparent_proxy=dict(type="bool", required=False),
            enable_evaluate_policy_on_global_ssl_bypass=dict(type="bool", required=False),
            enable_office365=dict(type="bool", required=False),

            log_internal_ip=dict(type="bool", required=False),
            enforce_surrogate_ip_for_windows_app=dict(type="bool", required=False),
            track_http_tunnel_on_http_ports=dict(type="bool", required=False),
            block_http_tunnel_on_non_http_ports=dict(type="bool", required=False),
            block_domain_fronting_on_host_header=dict(type="bool", required=False),
            zscaler_client_connector1_and_pac_road_warrior_in_firewall=dict(type="bool", required=False),
            cascade_url_filtering=dict(type="bool", required=False),
            enable_policy_for_unauthenticated_traffic=dict(type="bool", required=False),
            block_non_compliant_http_request_on_http_ports=dict(type="bool", required=False),
            enable_admin_rank_access=dict(type="bool", required=False),

            http2_nonbrowser_traffic_enabled=dict(type="bool", required=False),
            ecs_for_all_enabled=dict(type="bool", required=False),
            dynamic_user_risk_enabled=dict(type="bool", required=False),
            block_connect_host_sni_mismatch=dict(type="bool", required=False),
            prefer_sni_over_conn_host=dict(type="bool", required=False),
            sipa_xff_header_enabled=dict(type="bool", required=False),
            block_non_http_on_http_port_enabled=dict(type="bool", required=False),

            ui_session_timeout=dict(type="int", required=False),
            ecs_object=dict(
                type="dict",
                required=False,
                options=dict(
                    id=dict(type="int", required=False),
                    name=dict(type="str", required=False),
                    external_id=dict(type="str", required=False),
                ),
            ),

            auth_bypass_apps=dict(type="list", elements="str", required=False),
            kerberos_bypass_apps=dict(type="list", elements="str", required=False),
            basic_bypass_apps=dict(type="list", elements="str", required=False),
            digest_auth_bypass_apps=dict(type="list", elements="str", required=False),

            dns_resolution_on_transparent_proxy_exempt_apps=dict(type="list", elements="str", required=False),
            dns_resolution_on_transparent_proxy_ipv6_exempt_apps=dict(type="list", elements="str", required=False),
            dns_resolution_on_transparent_proxy_apps=dict(type="list", elements="str", required=False),
            dns_resolution_on_transparent_proxy_ipv6_apps=dict(type="list", elements="str", required=False),

            block_domain_fronting_apps=dict(type="list", elements="str", required=False),
            prefer_sni_over_conn_host_apps=dict(type="list", elements="str", required=False),

            dns_resolution_on_transparent_proxy_exempt_url_categories=dict(type="list", elements="str", required=False),
            dns_resolution_on_transparent_proxy_ipv6_exempt_url_categories=dict(type="list", elements="str", required=False),
            dns_resolution_on_transparent_proxy_url_categories=dict(type="list", elements="str", required=False),
            dns_resolution_on_transparent_proxy_ipv6_url_categories=dict(type="list", elements="str", required=False),

            auth_bypass_url_categories=dict(type="list", elements="str", required=False),
            domain_fronting_bypass_url_categories=dict(type="list", elements="str", required=False),
            kerberos_bypass_url_categories=dict(type="list", elements="str", required=False),
            basic_bypass_url_categories=dict(type="list", elements="str", required=False),
            http_range_header_remove_url_categories=dict(type="list", elements="str", required=False),
            digest_auth_bypass_url_categories=dict(type="list", elements="str", required=False),
            sni_dns_optimization_bypass_url_categories=dict(type="list", elements="str", required=False),
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
