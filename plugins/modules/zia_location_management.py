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
notes:
    - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
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
  city:
    description: "Geolocation of the IoT device."
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
  ssl_scan_enabled:
    description:
      - "This parameter was deprecated and no longer has an effect on SSL policy."
      - "It remains supported in the API payload in order to maintain backwards compatibility with existing scripts, but it will be removed in future."
      - "Enable SSL Inspection."
      - "Set to true in order to apply your SSL Inspection policy to HTTPS traffic."
      - To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/zia/deploying-ssl-inspection)
    type: bool
    required: false
  zapp_ssl_scan_enabled:
    description:
      - "This parameter was deprecated and no longer has an effect on SSL policy."
      - "It remains supported in the API payload in order to maintain backwards compatibility with existing scripts, but it will be removed in future."
      - "Enable Zscaler App SSL Setting."
      - "When set to true, the Zscaler App SSL Scan Setting takes effect, irrespective of the SSL policy that is configured for the location."
      - To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/z-app/configuring-ssl-inspection-zscaler-app#configure-SSL-Zscaler-App)
    type: bool
    required: false
  xff_forward_enabled:
    description:
      - "Enable XFF Forwarding for a location."
      - "When set to true, traffic is passed to Zscaler Cloud via the X-Forwarded-For (XFF) header."
      - "Note: For sublocations, this attribute is a read-only field as the value is inherited from the parent location."
    type: bool
    required: false
  surrogate_ip:
    description:
      - "Enable Surrogate IP. When set to true, users are mapped to internal device IP addresses."
      - "To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/zia/about-surrogate-ip)"
    type: bool
    required: false
  idle_time_in_minutes:
    description: "Idle Time to Disassociation. The user mapping idle time (in minutes) is required if a Surrogate IP is enabled."
    type: int
    required: false
  display_time_unit:
    description: "Display Time Unit. The time unit to display for IP Surrogate idle time to disassociation."
    type: str
    required: false
    choices:
      - MINUTE
      - HOUR
      - DAY
  surrogate_ip_enforced_for_known_browsers:
    description:
      - "Enforce Surrogate IP for Known Browsers. When set to true, IP Surrogate is enforced for all known browsers."
      - "To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/zia/about-surrogate-ip)"
    type: bool
    required: false
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
      - MINUTE
      - HOUR
      - DAY
  ofw_enabled:
    description: "Enable Firewall. When set to true, Firewall is enabled for the location."
    type: bool
    required: false
  ips_control:
    description: "Enable IPS Control. When set to true, IPS Control is enabled for the location if Firewall is enabled."
    type: bool
    required: false
  aup_enabled:
    description:
      - "Enable AUP. When set to true, AUP is enabled for the location."
      - "To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/zia/about-end-user-notifications)"
    type: bool
    required: false
  caution_enabled:
    description:
      - "Enable Caution. When set to true, a caution notifcation is enabled for the location."
      - "To Learn More, see Deploying SSL Inspection U(https://help.zscaler.com/zia/configuring-caution-notification#caution-interval)"
    type: bool
    required: false
  aup_block_internet_until_accepted:
    description:
      - "For First Time AUP Behavior, Block Internet Access."
      - "When set, all internet access (including non-HTTP traffic) is disabled until the user accepts the AUP."
    type: bool
    required: false
  aup_force_ssl_inspection:
    description:
      - "For First Time AUP Behavior, Force SSL Inspection."
      - "When set, Zscaler forces SSL Inspection in order to enforce AUP for HTTPS traffic."
    type: bool
    required: false
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
  iot_enforce_policy_set:
    description: "Enforces IOT Policy set"
    type: bool
    required: false
  geo_override:
    description: "If this field is set to true, the latitude and longitude values must be provided. By default, it's set to false."
    type: bool
    required: false
  ipv6_enabled:
    description: "If set to true, IPv6 is enabled for the location and IPv6 traffic from the location can be forwarded"
    type: bool
    required: false
  ipv6_dns64_prefix:
    description: "Name-ID pair of the NAT64 prefix configured as the DNS64 prefix for the location"
    type: bool
    required: false
  latitude:
    description:
      - Required only if the geoOverride attribute is set.
      - Latitude with 7 digit precision after decimal point, ranges between -90 and 90 degrees.
    required: false
    type: float
  longitude:
    description:
      - Required only if the geoOverride attribute is set.
      - Longitude with 7 digit precision after decimal point, ranges between -180 and 180 degrees.
    required: false
    type: float
  other_sub_location:
    description: "If set to true, indicates that this is a default sub-location created by the Zscaler service to accommodate IPv4 addresses"
    type: bool
    required: false
  other6_sub_location:
    description: "If set to true, indicates that this is a default sub-location created by the Zscaler service to accommodate IPv6 addresses"
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

EXAMPLES = r"""
- name: Create UFQDN VPN Credential.
  zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials:
    type: "UFQDN"
    fqdn: "usa_sjc37@acme.com"
    comments: "Created via Ansible"
    pre_shared_key: "************!"
  register: vpn_credential_ufqdn

- name: Create Location Management with UFQDN VPN Type
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
    vpn_credentials:
      - id: "{{ vpn_credential_ufqdn.data.id }}"
        type: "{{ vpn_credential_ufqdn.data.type }}"

# Create Location Management with VPN IP Type
- name: Create/Update/Delete a Static IP.
  zscaler.ziacloud.zia_traffic_forwarding_static_ip:
    provider: '{{ provider }}'
    ip_address: "1.1.1.1"
    routable_ip: true
    comment: "Created with Ansible"
    geo_override: true
    latitude: "-36.848461"
    longitude: "174.763336"
  register: static_ip

- name: Create/Update/Delete VPN Credentials Type IP.
  zscaler.ziacloud.zia_location_management:
    type: "IP"
    ip_address: "static_ip.data.ip_address"
    comments: "Created via Ansible"
    pre_shared_key: "*************"
  register: vpn_credential_ip

- name: Create Location Management with IP VPN Type
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
    ip_addresses: "static_ip.data.ip_address"
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
    Normalize location data by removing known server-populated or read-only fields.
    """
    normalized = location.copy()

    computed_values = [
        "id",
        "comments",
        "child_count",
        "cookies_and_proxy",
        "default_extranet_dns",
        "default_extranet_ts_pool",
        "digest_auth_enabled",
        "dynamiclocation_groups",
        "ec_location",
        "exclude_from_dynamic_groups",
        "exclude_from_manual_groups",
        "extranet",
        "extranet_dns",
        "extranet_ip_pool",
        "kerberos_auth",
        "language",
        "match_in_child",
        "non_editable",
        "static_location_groups",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def normalize_vpn_credentials(vpn_creds):
    """
    Normalize the VPN credentials list to ensure consistent keys and ignore read-only fields.
    """
    if not vpn_creds:
        return []

    normalized_creds = []
    for cred in vpn_creds:
        # 'ipAddress' is how the API typically returns it; unify to 'ipAddress' internally
        ip_val = cred.get("ip_address", cred.get("ipAddress"))
        normalized_cred = {
            "id": cred.get("id"),
            "type": cred.get("type"),
            "fqdn": cred.get("fqdn"),
            "ipAddress": ip_val,
        }
        # If the API returns "comments" or other read-only fields in the credential,
        # we simply don't include them in normalized_cred.
        normalized_creds.append(normalized_cred)
    return normalized_creds


def core(module):
    client = ZIAClientHelper(module)
    state = module.params.get("state", "present")

    # Build a dict of the "desired" fields from Ansible
    location_mgmt = {}
    params = [
        "id",
        "name",
        "parent_id",
        "up_bandwidth",
        "dn_bandwidth",
        "country",
        "city",
        "tz",
        "ip_addresses",
        "ports",
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
        "geo_override",
        "latitude",
        "longitude",
        "other_sub_location",
        "other6_sub_location",
        "ipv6_enabled",
        "ipv6_dns64_prefix",
        "iot_discovery_enabled",
        "iot_enforce_policy_set",
    ]
    for p in params:
        location_mgmt[p] = module.params.get(p)

    # Normalize the VPN creds from user input
    location_mgmt["vpn_credentials"] = normalize_vpn_credentials(
        module.params.get("vpn_credentials", [])
    )

    validate_location_mgmt(location_mgmt)

    # Set defaults if not provided
    if location_mgmt["parent_id"] is None:
        location_mgmt["parent_id"] = 0
    if location_mgmt["aup_enabled"] is None:
        location_mgmt["aup_enabled"] = False
    if location_mgmt["aup_timeout_in_days"] is None:
        location_mgmt["aup_timeout_in_days"] = 0
    if location_mgmt["profile"] is None:
        location_mgmt["profile"] = "CORPORATE"

    # Look up existing resource if we have either an id or a name
    existing_location_mgmt = None
    if location_mgmt["id"]:
        existing_location_mgmt = client.locations.get_location(
            location_id=location_mgmt["id"]
        )
    elif location_mgmt["name"]:
        existing_location_mgmt = client.locations.get_location(
            location_name=location_mgmt["name"]
        )

    # Normalize server's current location data and local "desired" data
    desired_location = normalize_location(location_mgmt)
    current_location = (
        normalize_location(existing_location_mgmt) if existing_location_mgmt else {}
    )

    # Compare differences
    differences_detected = False
    differences_summary = {}

    for key in desired_location:
        desired_value = desired_location[key]
        current_value = current_location.get(key)

        # If it's vpn_credentials, compare the normalized lists only
        if key == "vpn_credentials":
            normalized_current_creds = normalize_vpn_credentials(current_value)
            normalized_desired_creds = normalize_vpn_credentials(desired_value)

            if normalized_current_creds != normalized_desired_creds:
                differences_detected = True
                differences_summary[key] = {
                    "current": normalized_current_creds,
                    "desired": normalized_desired_creds,
                }
                module.warn(
                    f"Difference detected in {key}. "
                    f"Current: {normalized_current_creds}, "
                    f"Desired: {normalized_desired_creds}"
                )
        else:
            # If desired is None, skip. (Means we didn't want to set that field at all)
            if desired_value is None:
                continue

            if desired_value != current_value:
                differences_detected = True
                differences_summary[key] = {
                    "current": current_value,
                    "desired": desired_value,
                }
                module.warn(
                    f"Difference detected in {key}. "
                    f"Current: {current_value}, "
                    f"Desired: {desired_value}"
                )

    # Honor check_mode
    if module.check_mode:
        if differences_detected:
            module.exit_json(changed=True, differences=differences_summary)
        else:
            module.exit_json(changed=False)

    # Proceed with create/update/delete
    if state == "present":
        if existing_location_mgmt:
            # We already have a location; update if needed
            location_id = existing_location_mgmt["id"]
            if differences_detected:
                # Filter out any None values
                update_location = deleteNone(desired_location)
                module.warn(f"Payload Update for SDK: {update_location}")
                try:
                    updated_location = client.locations.update_location(
                        location_id, **update_location
                    ).to_dict()
                    module.exit_json(changed=True, data=updated_location)
                except Exception as e:
                    module.fail_json(msg=f"Failed to update location: {e}")
            else:
                # Nothing to do
                module.exit_json(changed=False, data=existing_location_mgmt)
        else:
            # Create new location
            create_location = deleteNone(desired_location)
            module.warn(f"Payload for SDK: {create_location}")
            try:
                new_location = client.locations.add_location(**create_location)
                module.exit_json(changed=True, data=new_location)
            except Exception as e:
                module.fail_json(msg=f"Failed to create location: {e}")
    else:  # state == "absent"
        if existing_location_mgmt:
            try:
                client.locations.delete_location(existing_location_mgmt["id"])
                module.exit_json(changed=True, message="Location deleted successfully.")
            except Exception as e:
                module.fail_json(msg=f"Failed to delete location: {e}")
        else:
            module.exit_json(
                changed=False, message="Location not found, nothing to delete."
            )


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        parent_id=dict(type="int", required=False),
        description=dict(type="str", required=False),
        country=dict(type="str", required=False),
        city=dict(type="str", required=False),
        tz=dict(type="str", required=False),
        geo_override=dict(type="bool", required=False),
        latitude=dict(type="float", required=False),
        longitude=dict(type="float", required=False),
        ip_addresses=dict(type="list", elements="str", required=False),
        ports=dict(type="list", elements="int", required=False),
        auth_required=dict(type="bool", required=False),
        ssl_scan_enabled=dict(type="bool", required=False),
        zapp_ssl_scan_enabled=dict(type="bool", required=False),
        xff_forward_enabled=dict(type="bool", required=False),
        surrogate_ip=dict(type="bool", required=False),
        idle_time_in_minutes=dict(type="int", required=False),
        display_time_unit=dict(
            type="str", required=False, choices=["MINUTE", "HOUR", "DAY"]
        ),
        surrogate_ip_enforced_for_known_browsers=dict(type="bool", required=False),
        surrogate_refresh_time_in_minutes=dict(type="int", required=False),
        surrogate_refresh_time_unit=dict(
            type="str", required=False, choices=["MINUTE", "HOUR", "DAY"]
        ),
        other_sub_location=dict(type="bool", required=False),
        other6_sub_location=dict(type="bool", required=False),
        ofw_enabled=dict(type="bool", required=False),
        ips_control=dict(type="bool", required=False),
        aup_enabled=dict(type="bool", required=False),
        aup_block_internet_until_accepted=dict(type="bool", required=False),
        aup_force_ssl_inspection=dict(type="bool", required=False),
        aup_timeout_in_days=dict(type="int", required=False),
        caution_enabled=dict(type="bool", required=False),
        ipv6_enabled=dict(type="bool", required=False),
        ipv6_dns64_prefix=dict(type="bool", required=False),
        iot_discovery_enabled=dict(type="bool", required=False),
        iot_enforce_policy_set=dict(type="bool", required=False),
        up_bandwidth=dict(type="int", required=False),
        dn_bandwidth=dict(type="int", required=False),
        profile=dict(
            type="str",
            default="NONE",
            choices=["NONE", "CORPORATE", "SERVER", "GUESTWIFI", "IOT"],
        ),
        vpn_credentials=dict(
            type="list",
            elements="dict",
            options=dict(
                id=dict(type="int", required=False),
                type=dict(type="str", default="UFQDN", choices=["UFQDN", "IP"]),
                fqdn=dict(type="str", required=False),
                ip_address=dict(type="str", required=False),
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
