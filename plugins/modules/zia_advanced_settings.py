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
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)

def normalize_settings(data: dict) -> dict:
    """Normalize current and desired EUN values by removing computed fields and empty strings."""
    if not data:
        return {}

    result = {}
    for k, v in data.items():
        if isinstance(v, str) and v.strip() == "":
            continue  # Skip blank strings
        result[k] = v
    return result


def core(module):
    state = module.params.get("state")
    if state != "present":
        module.fail_json(msg="Only 'present' is supported for this module.")

    client = ZIAClientHelper(module)

    # Define all valid fields supported in the EUN payload
    params = [
        "auth_bypass_urls", "kerberos_bypass_urls", "digest_auth_bypass_urls",
        "dns_resolution_on_transparent_proxy_exempt_urls", "dns_resolution_on_transparent_proxy_urls",
        "enable_dns_resolution_on_transparent_proxy", "enable_ipv6_dns_resolution_on_transparent_proxy",
        "enable_ipv6_dns_optimization_on_all_transparent_proxy", "enable_evaluate_policy_on_global_ssl_bypass",
        "enable_office365", "log_internal_ip", "enforce_surrogate_ip_for_windows_app", "track_http_tunnel_on_http_ports",
        "block_http_tunnel_on_non_http_ports", "block_domain_fronting_on_host_header", "zscaler_client_connector1_and_pac_road_warrior_in_firewall",
        "cascade_url_filtering", "enable_policy_for_unauthenticated_traffic", "block_non_compliant_http_request_on_http_ports",
        "enable_admin_rank_access", "http2_nonbrowser_traffic_enabled", "ecs_for_all_enabled", "dynamic_user_risk_enabled",
        "block_connect_host_sni_mismatch", "prefer_sni_over_conn_host", "sipa_xff_header_enabled", "block_non_http_on_http_port_enabled",
        "ui_session_timeout", "ecs_object", "auth_bypass_apps", "kerberos_bypass_apps", "basic_bypass_apps", "digest_auth_bypass_apps",
        "dns_resolution_on_transparent_proxy_exempt_apps", "dns_resolution_on_transparent_proxy_ipv6_exempt_apps",
        "dns_resolution_on_transparent_proxy_apps", "dns_resolution_on_transparent_proxy_ipv6_apps",
        "block_domain_fronting_apps", "prefer_sni_over_conn_host_apps", "dns_resolution_on_transparent_proxy_exempt_url_categories",
        "dns_resolution_on_transparent_proxy_ipv6_exempt_url_categories", "dns_resolution_on_transparent_proxy_url_categories",
        "dns_resolution_on_transparent_proxy_ipv6_url_categories", "auth_bypass_url_categories", "domain_fronting_bypass_url_categories",
        "kerberos_bypass_url_categories", "basic_bypass_url_categories", "http_range_header_remove_url_categories",
        "digest_auth_bypass_url_categories", "sni_dns_optimization_bypass_url_categories"
    ]


    settings_data = {
        k: module.params.get(k)
        for k in params
        if module.params.get(k) is not None
           and not (isinstance(module.params.get(k), str) and module.params.get(k).strip() == "")
    }

    # 1) Fetch current EUN settings from the SDK
    current_settings, _, error = client.advanced_settings.get_advanced_settings()
    if error:
        module.fail_json(msg=f"Error fetching end user notification settings: {to_native(error)}")

    # 2) Convert both current/desired data to normalized dicts
    current_dict = normalize_settings(current_settings.as_dict())
    desired_dict = normalize_settings(settings_data)

    # module.warn(f"🧪 Raw keys from SDK: {list(current_dict.keys())}")
    module.warn(f"🔍 Current settings: {current_dict}")
    module.warn(f"📅 Desired settings: {desired_dict}")

    # Normalize unordered list attributes to prevent drift due to order
    for k in desired_dict:
        if isinstance(desired_dict[k], list) and isinstance(current_dict.get(k), list):
            desired_dict[k] = sorted(desired_dict[k])
            current_dict[k] = sorted(current_dict[k])

    # Then perform the drift check
    diff_keys = []
    for k in desired_dict:
        if current_dict.get(k) != desired_dict.get(k):
            diff_keys.append(k)

    drift = bool(diff_keys)
    module.warn(f"🧠 Drift detected: {drift}")

    if drift:
        module.warn("🔎 Drift found in these keys:")
        for k in diff_keys:
            module.warn(f"  {k}: current={current_dict.get(k)}, desired={desired_dict.get(k)}")

    # 4) Respect check_mode
    if module.check_mode:
        module.exit_json(changed=drift)

    # 5) If drift, update the resource
    if drift:
        # Update current settings object with the desired values
        for k, v in desired_dict.items():
            setattr(current_settings, k, v)

        # Convert the updated object to a request payload
        payload = deleteNone(current_settings.as_dict())

        for k, v in payload.items():
            setattr(current_settings, k, v)

        module.warn(f"🧼 Cleaned payload sent to SDK: {payload}")

        updated, _, error = client.advanced_settings.update_advanced_settings(current_settings)
        if error:
            module.fail_json(msg=f"Error updating end user notification settings: {to_native(error)}")

        module.exit_json(changed=True, end_user_notifications=updated.as_dict())
    else:
        module.exit_json(changed=False, msg="No drift detected; nothing to update.")


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(dict(
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
            state=dict(type="str", choices=["present"], default="present")
    ))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
