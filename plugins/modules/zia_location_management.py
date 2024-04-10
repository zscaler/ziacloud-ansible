#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Technology Alliances, <zscaler-partner-labs@z-bd.com>

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

DOCUMENTATION = """
---
module: zia_location_management
short_description: "Adds new locations and sub-locations."
description:
  - "Adds new locations and sub-locations."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.state
options:
  id:
    description: "Location ID"
    type: int
  name:
    description: "Location Name"
    type: str
    required: true
  parent_id:
    description:
      - "Parent Location ID."
      - "If this ID does not exist or is 0, it is implied that it is a parent location."
      - "Otherwise it is a sub-location whose parent has this ID. x-applicableTo: SUB"
    type: int
    required: false
  up_bandwidth:
    description: "Upload bandwidth in kbps. The value 0 implies no Bandwidth Control enforcement."
    type: int
    required: false
  dn_bandwidth:
    description: "Download bandwidth in kbps. The value 0 implies no Bandwidth Control enforcement."
    type: int
    required: false
  country:
    description: "Country Name"
    type: str
    required: false
  tz:
    description: "Timezone of the location. If not specified, it defaults to GMT."
    type: str
    required: false
  ip_addresses:
    description:
      - "For locations: IP addresses of the egress points that are provisioned in the Zscaler Cloud."
      - "Each entry is a single IP address (e.g., 238.10.33.9)."
      - "For sublocations: Egress, internal, or GRE tunnel IP addresses."
      - "Each entry is either a single IP address, CIDR (e.g., 10.10.33.0/24), or range (e.g., 10.10.33.1-10.10.33.10))."
    type: list
    elements: str
    required: false
  ports:
    description: "IP ports that are associated with the location."
    type: list
    elements: int
    required: false
  auth_required:
    description: "Enforce Authentication. Required when ports are enabled, IP Surrogate is enabled, or Kerberos Authentication is enabled."
    type: bool
    required: false
    default: false
  ssl_scan_enabled:
    description:
      - "This parameter was deprecated and no longer has an effect on SSL policy."
      - "It remains supported in the API payload in order to maintain backwards compatibility with existing scripts, but it will be removed in future."
      - Enable SSL Inspection. Set to true in order to apply your SSL Inspection policy to HTTPS traffic in the location and inspect HTTPS transactions for data leakage, malicious content, and viruses.
      - To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/zia/deploying-ssl-inspection)
    type: bool
    required: false
    default: false
  zapp_ssl_scan_enabled:
    description:
      - "This parameter was deprecated and no longer has an effect on SSL policy."
      - "It remains supported in the API payload in order to maintain backwards compatibility with existing scripts, but it will be removed in future."
      - "Enable Zscaler App SSL Setting. When set to true, the Zscaler App SSL Scan Setting takes effect, irrespective of the SSL policy that is configured for the location."
      - To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/z-app/configuring-ssl-inspection-zscaler-app#configure-SSL-Zscaler-App)
    type: bool
    required: false
    default: false
  xff_forward_enabled:
    description:
      - "Enable XFF Forwarding for a location. When set to true, traffic is passed to Zscaler Cloud via the X-Forwarded-For (XFF) header."
      - "Note: For sublocations, this attribute is a read-only field as the value is inherited from the parent location."
    type: bool
    required: false
    default: false
  surrogate_ip:
    description:
      - "Enable Surrogate IP. When set to true, users are mapped to internal device IP addresses."
      - "To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/zia/about-surrogate-ip)"
    type: bool
    required: false
    default: false
  idle_time_in_minutes:
    description: "Idle Time to Disassociation. The user mapping idle time (in minutes) is required if a Surrogate IP is enabled."
    type: int
    required: false
  display_time_unit:
    description: "Display Time Unit. The time unit to display for IP Surrogate idle time to disassociation."
    type: str
    required: false
  surrogate_ip_enforced_for_known_browsers:
    description:
      - "Enforce Surrogate IP for Known Browsers. When set to true, IP Surrogate is enforced for all known browsers."
      - "To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/zia/about-surrogate-ip)"
    type: bool
    required: false
    default: false
  surrogate_refresh_time_in_minutes:
    description:
      - "Refresh Time for re-validation of Surrogacy."
      - "The surrogate refresh time (in minutes) to re-validate the IP surrogates."
    type: int
    required: false
  surrogate_refresh_time_unit:
    description:
      - "Display Refresh Time Unit."
      - "The time unit to display for refresh time for re-validation of surrogacy."
    type: str
    required: false
    choices:
      - 'MINUTE'
      - 'HOUR'
      - 'DAY'
  ofw_enabled:
    description: "Enable Firewall. When set to true, Firewall is enabled for the location."
    type: bool
    required: false
    default: false
  ips_control:
    description: "Enable IPS Control. When set to true, IPS Control is enabled for the location if Firewall is enabled."
    type: bool
    required: false
    default: false
  aup_enabled:
    description:
      - "Enable AUP. When set to true, AUP is enabled for the location."
      - "To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/zia/about-end-user-notifications)"
    type: bool
    required: false
    default: false
  caution_enabled:
    description:
      - "Enable Caution. When set to true, a caution notifcation is enabled for the location."
      - "To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/zia/configuring-caution-notification#caution-interval)"
    type: bool
    required: false
    default: false
  aup_block_internet_until_accepted:
    description:
      - "For First Time AUP Behavior, Block Internet Access."
      - "When set, all internet access (including non-HTTP traffic) is disabled until the user accepts the AUP."
    type: bool
    required: false
    default: false
  aup_force_ssl_inspection:
    description:
      - "For First Time AUP Behavior, Force SSL Inspection."
      - "When set, Zscaler forces SSL Inspection in order to enforce AUP for HTTPS traffic."
    type: bool
    required: false
    default: false
  aup_timeout_in_days:
    description: "Custom AUP Frequency. Refresh time (in days) to re-validate the AUP."
    type: int
    required: false
  profile:
    description:
      - "(Optional) Profile tag that specifies the location traffic type."
      - "The criteria used for setting best possible value is as follows:"
      - "When invoked with a partner API key, it automatically sets the profile attribute to CORPORATE."
      - "When invoked using public API, it automatically sets the profile attribute based on the following criteria:"
      - "If the location has authentication enabled, then it sets profile to CORPORATE."
      - "If the location has authentication disabled and name contains guest, then it sets profile to GUESTWIFI."
      - "For all other locations with authentication disabled, it sets profile to SERVER."
    type: str
    default: NONE
    choices: ['NONE', 'CORPORATE', 'SERVER', 'GUESTWIFI', 'IOT']
  iot_discovery_enabled:
    description: "If this field is set to true, IoT discovery is enabled for this location."
    type: bool
    required: false
  description:
    description: "Additional notes or information regarding the location or sub-location. The description cannot exceed 1024 characters."
    type: str
    required: false
  vpn_credentials:
    description: "VPN User Credentials that are associated with the location."
    type: list
    elements: dict
    required: false
    suboptions:
      id:
        description: "VPN credential id"
        type: int
        required: false
      type:
        description:
          - "VPN authentication type (i.e., how the VPN credential is sent to the server)."
          - It is not modifiable after VpnCredential is created."
        type: str
        default: UFQDN
        choices: ['UFQDN', 'IP']
      fqdn:
        description: "Fully Qualified Domain Name. Applicable only to UFQDN (or HOSTED_MOBILE_USERS) auth type."
        type: str
        required: false
      ip_address:
        description:
          - "Static IP address for VPN that is self-provisioned or provisioned by Zscaler."
          - "This is a required field for IP auth type and is not applicable to other auth types."
          - "Note: If you want Zscaler to provision static IP addresses for your organization, contact Zscaler Support."
        type: str
        required: false
"""

EXAMPLES = """
- name: Create/Update/Delete Location.
  zscaler.ziacloud.zia_location_management:
    type: "UFQDN"
    fqdn: "usa_sjc37@acme.com"
    comments: "Created via Ansible"
    pre_shared_key: "newPassword123!"
  register: vpn_credential_ufqdn

- name: Gather Information Details of a ZIA User Role
  zscaler.ziacloud.zia_location_management:
    name: "USA_SJC_37"
    description: "Created with Ansible"
    country: "UNITED_STATES"
    tz: "UNITED_STATES_AMERICA_LOS_ANGELES"
    auth_required: true
    idle_time_in_minutes: 720
    display_time_unit: "HOUR"
    surrogate_ip: true
    xff_forward_enabled: true
    ofw_enabled: true
    ips_control: true
    ip_addresses: "1.1.1.1"
    vpn_credentials:
        - id: "{{ vpn_credential_ufqdn.data.id }}"
          type: "{{ vpn_credential_ufqdn.data.type }}"

- name: Create/Update/Delete VPN Credentials Type IP.
  zscaler.ziacloud.zia_location_management:
    type: "IP"
    ip_address: "1.1.1.1"
    comments: "Created via Ansible"
    pre_shared_key: "newPassword123!"
  register: vpn_credential_ip

- name: Gather Information Details of a ZIA User Role
  zscaler.ziacloud.zia_location_management:
    name: "USA_SJC_37"
    description: "Created with Ansible"
    country: "UNITED_STATES"
    tz: "UNITED_STATES_AMERICA_LOS_ANGELES"
    auth_required: true
    idle_time_in_minutes: 720
    display_time_unit: "HOUR"
    surrogate_ip: true
    xff_forward_enabled: true
    ofw_enabled: true
    ips_control: true
    ip_addresses: "1.1.1.1"
    vpn_credentials:
        - id: "{{ vpn_credential_ip.data.id }}"
          type: "{{ vpn_credential_ip.data.type }}"
          ip_address: "{{ vpn_credential_ip.data.ip_address }}"
"""

RETURN = """
# The newly created location resource record.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
    validate_location_mgmt,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_location(location):
    """
    Normalize location data by setting computed values.
    """
    normalized = location.copy()

    computed_values = [
        "id",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def normalize_vpn_credentials(vpn_creds):
    """
    Normalize the VPN credentials list to have consistent keys for comparison.
    If vpn_creds is None, return an empty list.
    """
    if vpn_creds is None:
        return []

    normalized_creds = []
    for cred in vpn_creds:
        # Ensure all required keys are present, set to None if missing
        normalized_cred = {
            "id": cred.get("id"),
            "type": cred.get("type"),
            "fqdn": cred.get("fqdn"),
            "ip_address": cred.get("ip_address"),
            "pre_shared_key": cred.get("pre_shared_key"),
        }
        normalized_creds.append(normalized_cred)
    return normalized_creds


def core(module):
    client = ZIAClientHelper(module)
    state = module.params.get("state", None)
    location_mgmt = dict()
    params = [
        "id",
        "name",
        "parent_id",
        "up_bandwidth",
        "dn_bandwidth",
        "country",
        "tz",
        "ip_addresses",
        "ports",
        "vpn_credentials",
        "auth_required",
        "ssl_scan_enabled",
        "zapp_ssl_scan_enabled",
        "xff_forward_enabled",
        "surrogate_ip",
        "idle_time_in_minutes",
        "display_time_unit",
        "surrogate_ip_enforced_for_known_browsers",
        "surrogate_refresh_time_in_minutes",
        "surrogate_refresh_time_unit",
        "ofw_enabled",
        "ips_control",
        "aup_enabled",
        "caution_enabled",
        "aup_block_internet_until_accepted",
        "aup_force_ssl_inspection",
        "aup_timeout_in_days",
        "profile",
        "description",
    ]
    for param_name in params:
        location_mgmt[param_name] = module.params.get(param_name, None)

    validate_location_mgmt(location_mgmt)

    # Set default values for attributes that have system defaults
    if location_mgmt["parent_id"] is None:
        location_mgmt["parent_id"] = 0  # Assuming 0 is the system default
    if location_mgmt["aup_enabled"] is None:
        location_mgmt["aup_enabled"] = False  # Default behavior if not specified
    if location_mgmt["aup_timeout_in_days"] is None:
        location_mgmt["aup_timeout_in_days"] = 0  # Default value
    if location_mgmt["profile"] is None:
        location_mgmt["profile"] = "CORPORATE"  # Default or retain current state

    location_name = location_mgmt.get("name", None)
    location_id = location_mgmt.get("id", None)

    existing_location_mgmt = None
    if location_id is not None:
        locationBox = client.locations.get_location(location_id=location_id)
        if locationBox is not None:
            existing_location_mgmt = locationBox.to_dict()
    elif location_name is not None:
        locationBox = client.locations.get_location(location_name=location_name)
        if locationBox is not None:
            existing_location_mgmt = locationBox.to_dict()

    # Normalize and compare existing and desired data
    desired_location = normalize_location(location_mgmt)
    current_location = (
        normalize_location(existing_location_mgmt) if existing_location_mgmt else {}
    )

    # Adjusted Comparison Logic
    differences_detected = False
    for key, desired_value in desired_location.items():
        current_value = current_location.get(key)

        # Special handling for lists/dictionaries
        if key == "vpn_credentials":
            # Normalize vpn_credentials for comparison
            normalized_current_creds = normalize_vpn_credentials(current_value)
            normalized_desired_creds = normalize_vpn_credentials(desired_value)

            if normalized_current_creds != normalized_desired_creds:
                differences_detected = True
                module.warn(
                    f"Difference detected in {key}. Current: {normalized_current_creds}, Desired: {normalized_desired_creds}"
                )

        # Special handling for specific attributes
        if key in ["aup_enabled", "aup_timeout_in_days", "profile"]:
            # Your comparison logic for these attributes
            pass
        elif desired_value is None:
            # Skip updating this attribute if it's None (not specified)
            continue
        elif desired_value != current_value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
            )

    if existing_location_mgmt is not None:
        id = existing_location_mgmt.get("id")
        existing_location_mgmt.update(desired_location)
        existing_location_mgmt["id"] = id

    module.warn(f"Final payload being sent to SDK: {location_mgmt}")
    if state == "present":
        if existing_location_mgmt is not None:
            if differences_detected:
                """Update"""
                update_location = deleteNone(
                    dict(
                        location_id=existing_location_mgmt.get("id"),
                        name=existing_location_mgmt.get("name"),
                        parent_id=existing_location_mgmt.get("parent_id"),
                        up_bandwidth=existing_location_mgmt.get("up_bandwidth"),
                        dn_bandwidth=existing_location_mgmt.get("dn_bandwidth"),
                        country=existing_location_mgmt.get("country"),
                        tz=existing_location_mgmt.get("tz"),
                        ip_addresses=existing_location_mgmt.get("ip_addresses"),
                        ports=existing_location_mgmt.get("ports"),
                        vpn_credentials=existing_location_mgmt.get("vpn_credentials"),
                        auth_required=existing_location_mgmt.get("auth_required"),
                        ssl_scan_enabled=existing_location_mgmt.get("ssl_scan_enabled"),
                        zapp_ssl_scan_enabled=existing_location_mgmt.get(
                            "zapp_ssl_scan_enabled"
                        ),
                        xff_forward_enabled=existing_location_mgmt.get(
                            "xff_forward_enabled"
                        ),
                        surrogate_ip=existing_location_mgmt.get("surrogate_ip"),
                        idle_time_in_minutes=existing_location_mgmt.get(
                            "idle_time_in_minutes"
                        ),
                        display_time_unit=existing_location_mgmt.get(
                            "display_time_unit"
                        ),
                        surrogate_ip_enforced_for_known_browsers=existing_location_mgmt.get(
                            "surrogate_ip_enforced_for_known_browsers"
                        ),
                        surrogate_refresh_time_in_minutes=existing_location_mgmt.get(
                            "surrogate_refresh_time_in_minutes"
                        ),
                        surrogate_refresh_time_unit=existing_location_mgmt.get(
                            "surrogate_refresh_time_unit"
                        ),
                        ofw_enabled=existing_location_mgmt.get("ofw_enabled"),
                        ips_control=existing_location_mgmt.get("ips_control"),
                        aup_enabled=existing_location_mgmt.get("aup_enabled"),
                        caution_enabled=existing_location_mgmt.get("caution_enabled"),
                        aup_block_internet_until_accepted=existing_location_mgmt.get(
                            "aup_block_internet_until_accepted"
                        ),
                        aup_force_ssl_inspection=existing_location_mgmt.get(
                            "aup_force_ssl_inspection"
                        ),
                        aup_timeout_in_days=existing_location_mgmt.get(
                            "aup_timeout_in_days"
                        ),
                        managed_by=existing_location_mgmt.get("managed_by"),
                        profile=existing_location_mgmt.get("profile"),
                        description=existing_location_mgmt.get("description"),
                        iot_discovery_enabled=existing_location_mgmt.get(
                            "iot_discovery_enabled"
                        ),
                    )
                )
                module.warn("Payload Update for SDK: {}".format(update_location))
                updated_location = client.locations.update_location(
                    **update_location
                ).to_dict()
                module.exit_json(changed=True, data=updated_location)
        else:
            module.warn("Creating new location as no existing location found")
            """Create"""
            create_location = deleteNone(
                dict(
                    name=location_mgmt.get("name"),
                    parent_id=location_mgmt.get("parent_id"),
                    up_bandwidth=location_mgmt.get("up_bandwidth"),
                    dn_bandwidth=location_mgmt.get("dn_bandwidth"),
                    country=location_mgmt.get("country"),
                    tz=location_mgmt.get("tz"),
                    ip_addresses=location_mgmt.get("ip_addresses"),
                    ports=location_mgmt.get("ports"),
                    vpn_credentials=location_mgmt.get("vpn_credentials"),
                    auth_required=location_mgmt.get("auth_required"),
                    ssl_scan_enabled=location_mgmt.get("ssl_scan_enabled"),
                    zapp_ssl_scan_enabled=location_mgmt.get("zapp_ssl_scan_enabled"),
                    xff_forward_enabled=location_mgmt.get("xff_forward_enabled"),
                    surrogate_ip=location_mgmt.get("surrogate_ip"),
                    idle_time_in_minutes=location_mgmt.get("idle_time_in_minutes"),
                    display_time_unit=location_mgmt.get("display_time_unit"),
                    surrogate_ip_enforced_for_known_browsers=location_mgmt.get(
                        "surrogate_ip_enforced_for_known_browsers"
                    ),
                    surrogate_refresh_time_in_minutes=location_mgmt.get(
                        "surrogate_refresh_time_in_minutes"
                    ),
                    surrogate_refresh_time_unit=location_mgmt.get(
                        "surrogate_refresh_time_unit"
                    ),
                    ofw_enabled=location_mgmt.get("ofw_enabled"),
                    ips_control=location_mgmt.get("ips_control"),
                    aup_enabled=location_mgmt.get("aup_enabled"),
                    caution_enabled=location_mgmt.get("caution_enabled"),
                    aup_block_internet_until_accepted=location_mgmt.get(
                        "aup_block_internet_until_accepted"
                    ),
                    aup_force_ssl_inspection=location_mgmt.get(
                        "aup_force_ssl_inspection"
                    ),
                    aup_timeout_in_days=location_mgmt.get("aup_timeout_in_days"),
                    profile=location_mgmt.get("profile"),
                    description=location_mgmt.get("description"),
                    iot_discovery_enabled=location_mgmt.get("iot_discovery_enabled"),
                )
            )
            module.warn("Payload for SDK: {}".format(create_location))
            new_location = client.locations.add_location(**create_location)
            module.exit_json(changed=True, data=new_location)
    elif (
        state == "absent"
        and existing_location_mgmt is not None
        and existing_location_mgmt.get("id") is not None
    ):
        code = client.locations.delete_location(
            location_id=existing_location_mgmt.get("id")
        )
        if code > 299:
            module.exit_json(changed=False, data=None)
        module.exit_json(changed=True, data=existing_location_mgmt)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        parent_id=dict(type="int", required=False),
        up_bandwidth=dict(type="int", required=False),
        dn_bandwidth=dict(type="int", required=False),
        country=dict(type="str", required=False),
        tz=dict(type="str", required=False),
        ip_addresses=dict(type="list", elements="str", required=False),
        ports=dict(type="list", elements="int", required=False),
        auth_required=dict(type="bool", required=False),
        ssl_scan_enabled=dict(type="bool", required=False),
        zapp_ssl_scan_enabled=dict(type="bool", required=False),
        xff_forward_enabled=dict(type="bool", required=False),
        surrogate_ip=dict(type="bool", required=False),
        idle_time_in_minutes=dict(type="int", required=False),
        surrogate_ip_enforced_for_known_browsers=dict(type="bool", required=False),
        surrogate_refresh_time_in_minutes=dict(type="int", required=False),
        display_time_unit=dict(
            type="str",
            required=False,
            choices=["MINUTE", "HOUR", "DAY"],
        ),
        surrogate_refresh_time_unit=dict(
            type="str",
            required=False,
            choices=["MINUTE", "HOUR", "DAY"],
        ),
        ofw_enabled=dict(type="bool", required=False),
        ips_control=dict(type="bool", required=False),
        aup_enabled=dict(type="bool", required=False),
        caution_enabled=dict(type="bool", required=False),
        aup_block_internet_until_accepted=dict(type="bool", required=False),
        aup_force_ssl_inspection=dict(type="bool", required=False),
        iot_discovery_enabled=dict(type="bool", required=False),
        aup_timeout_in_days=dict(type="int", required=False),
        profile=dict(
            type="str",
            default="NONE",
            choices=["NONE", "CORPORATE", "SERVER", "GUESTWIFI", "IOT"],
        ),
        description=dict(type="str", required=False),
        vpn_credentials=dict(
            type="list",
            elements="dict",
            options=dict(
                id=dict(type="int", required=False),
                type=dict(type="str", default="UFQDN", choices=["UFQDN", "IP"]),
                fqdn=dict(type="str", required=False),
                ip_address=dict(type="str", required=False),
                pre_shared_key=dict(type="str", required=False),
            ),
            required=False,
        ),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
