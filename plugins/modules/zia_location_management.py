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
  sub_loc_scope_enabled:
    description:
      - "Indicates whether defining scopes is allowed for this sublocation."
      - "Sublocation scopes are available only for the Workload traffic type sublocations whose parent"
      - "locations are associated with Amazon Web Services (AWS) Cloud Connector groups."
    type: bool
    required: false
  sub_loc_scope:
    description:
      - "Defines a scope for the sublocation from the available types to segregate workload traffic"
      - "from a single sublocation to apply different Cloud Connector and ZIA security policies."
      - "This field is only available for the Workload traffic type sublocations whose parent"
      - "locations are associated with Amazon Web Services (AWS) Cloud Connector groups."
    type: str
    required: false
    choices: ['VPC_ENDPOINT', 'VPC', 'NAMESPACE', 'ACCOUNT']
  sub_loc_scope_values:
    description: "Specifies values for the selected sublocation scope type."
    type: list
    elements: str
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

# Create sub-location with sublocation scope (Workload traffic, AWS Cloud Connector)
- name: Create sub-location with sublocation scope
  zscaler.ziacloud.zia_location_management:
    name: "AWS_VPC_Sublocation"
    description: "Sublocation scoped by VPC for AWS Cloud Connector"
    parent_id: "{{ parent_location_id }}"
    sub_loc_scope: "VPC"
    sub_loc_scope_values:
      - "vpc-12345678"
      - "vpc-87654321"
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
import json


def normalize_location(location):
    """
    Normalize location data by removing computed values.
    """
    if not location:
        return {}

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
    Normalize VPN credentials to only include the fields we actually want to manage.
    For comparison purposes, we only care about id and type.
    """
    if not vpn_creds:
        return []

    return [
        {
            "id": cred["id"],
            "type": cred["type"].upper(),  # Normalize to uppercase for consistent comparison
        }
        for cred in vpn_creds
        if cred.get("id") and cred.get("type")
    ]


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)

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
        "sub_loc_scope_enabled",
        "sub_loc_scope",
        "sub_loc_scope_values",
        "ipv6_enabled",
        "ipv6_dns64_prefix",
        "iot_discovery_enabled",
        "iot_enforce_policy_set",
        "vpn_credentials",
    ]

    location_mgmt = {param: module.params.get(param) for param in params}

    # Normalize the VPN creds from user input
    location_mgmt["vpn_credentials"] = normalize_vpn_credentials(module.params.get("vpn_credentials", []))

    validate_location_mgmt(location_mgmt)

    location_id = location_mgmt.get("id")
    location_name = location_mgmt.get("name")

    existing_location = None
    if location_id is not None:
        result, _unused, error = client.locations.get_location(location_id=location_id)
        if error:
            module.fail_json(msg=f"Error fetching location with id {location_id}: {to_native(error)}")
        if result:
            existing_location = result.as_dict()
    else:
        # Use search to find locations including sublocations by name (fixes idempotency for sublocations)
        query_params = {"search": location_name} if location_name else {}
        result, _unused, error = client.locations.list_locations(query_params=query_params)
        if error:
            module.fail_json(msg=f"Error listing locations: {to_native(error)}")
        if result:
            parent_id = location_mgmt.get("parent_id")
            for location_ in result:
                if location_.name != location_name:
                    continue
                loc_dict = location_.as_dict()
                # For sublocations, also match parent_id to avoid confusing with same-named parent
                if parent_id is not None and parent_id != 0:
                    if loc_dict.get("parent_id") != parent_id:
                        continue
                existing_location = loc_dict
                break

    # Normalize server's current location data and local "desired" data
    desired_location = normalize_location(location_mgmt)
    current_location = normalize_location(existing_location) if existing_location else {}

    # Compare differences
    differences_detected = False
    differences_summary = {}

    for key in desired_location:
        desired_value = desired_location[key]
        current_value = current_location.get(key)

        # If it's vpn_credentials, compare the normalized lists only
        if key == "vpn_credentials":
            # Simplify comparison - only check id and type match
            current_ids_types = {(c["id"], c["type"].upper()) for c in (current_value or [])}
            desired_ids_types = {(c["id"], c["type"].upper()) for c in (desired_value or [])}

            if current_ids_types != desired_ids_types:
                differences_detected = True
                differences_summary[key] = {
                    "current": list(current_ids_types),
                    "desired": list(desired_ids_types),
                }
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
                module.warn(f"Difference detected in {key}. " f"Current: {current_value}, " f"Desired: {desired_value}")

    if module.check_mode:
        if state == "present" and (existing_location is None or differences_detected):
            module.exit_json(changed=True, differences=differences_summary)
        elif state == "absent" and existing_location is not None:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_location:
            if differences_detected:
                update_location = deleteNone(
                    {
                        "location_id": existing_location.get("id"),
                        "name": desired_location.get("name"),
                        "description": desired_location.get("description"),
                        "parent_id": desired_location.get("parent_id"),
                        "up_bandwidth": desired_location.get("up_bandwidth"),
                        "dn_bandwidth": desired_location.get("dn_bandwidth"),
                        "country": desired_location.get("country"),
                        "city": desired_location.get("city"),
                        "tz": desired_location.get("tz"),
                        "ip_addresses": desired_location.get("ip_addresses"),
                        "auth_required": desired_location.get("auth_required"),
                        "ssl_scan_enabled": desired_location.get("ssl_scan_enabled"),
                        "idle_time_in_minutes": desired_location.get("idle_time_in_minutes"),
                        "display_time_unit": desired_location.get("display_time_unit"),
                        "surrogate_ip": desired_location.get("surrogate_ip"),
                        "surrogate_ip_enforced_for_known_browsers": desired_location.get("surrogate_ip_enforced_for_known_browsers"),
                        "surrogate_refresh_time_in_minutes": desired_location.get("surrogate_refresh_time_in_minutes"),
                        "surrogate_refresh_time_unit": desired_location.get("surrogate_refresh_time_unit"),
                        "ofw_enabled": desired_location.get("ofw_enabled"),
                        "ips_control": desired_location.get("ips_control"),
                        "aup_enabled": desired_location.get("aup_enabled"),
                        "xff_forward_enabled": desired_location.get("xff_forward_enabled"),
                        "caution_enabled": desired_location.get("caution_enabled"),
                        "aup_block_internet_until_accepted": desired_location.get("aup_block_internet_until_accepted"),
                        "aup_force_ssl_inspection": desired_location.get("aup_force_ssl_inspection"),
                        "aup_timeout_in_days": desired_location.get("aup_timeout_in_days"),
                        "profile": desired_location.get("profile"),
                        "geo_override": desired_location.get("geo_override"),
                        "latitude": desired_location.get("latitude"),
                        "longitude": desired_location.get("longitude"),
                        "other_sub_location": desired_location.get("other_sub_location"),
                        "other6_sub_location": desired_location.get("other6_sub_location"),
                        "sub_loc_scope_enabled": desired_location.get("sub_loc_scope_enabled"),
                        "sub_loc_scope": desired_location.get("sub_loc_scope"),
                        "sub_loc_scope_values": desired_location.get("sub_loc_scope_values"),
                        "ipv6_enabled": desired_location.get("ipv6_enabled"),
                        "ipv6_dns64_prefix": desired_location.get("ipv6_dns64_prefix"),
                        "iot_discovery_enabled": desired_location.get("iot_discovery_enabled"),
                        "iot_enforce_policy_set": desired_location.get("iot_enforce_policy_set"),
                        "vpn_credentials": desired_location.get("vpn_credentials"),
                    }
                )
                module.warn("Payload Update for SDK: {}".format(update_location))
                module.warn("🚨 FINAL PAYLOAD: " + json.dumps(update_location, indent=2))
                updated_location, _unused, error = client.locations.update_location(**update_location)
                if error:
                    module.fail_json(msg=f"Error updating location: {to_native(error)}")
                module.exit_json(changed=True, data=updated_location.as_dict())
            else:
                module.exit_json(changed=False, data=existing_location)
        else:
            create_location = deleteNone(
                {
                    "name": desired_location.get("name"),
                    "description": desired_location.get("description"),
                    "parent_id": desired_location.get("parent_id"),
                    "up_bandwidth": desired_location.get("up_bandwidth"),
                    "dn_bandwidth": desired_location.get("dn_bandwidth"),
                    "city": desired_location.get("city"),
                    "country": desired_location.get("country"),
                    "tz": desired_location.get("tz"),
                    "ip_addresses": desired_location.get("ip_addresses"),
                    "auth_required": desired_location.get("auth_required"),
                    "ssl_scan_enabled": desired_location.get("ssl_scan_enabled"),
                    "idle_time_in_minutes": desired_location.get("idle_time_in_minutes"),
                    "display_time_unit": desired_location.get("display_time_unit"),
                    "surrogate_ip": desired_location.get("surrogate_ip"),
                    "surrogate_ip_enforced_for_known_browsers": desired_location.get("surrogate_ip_enforced_for_known_browsers"),
                    "surrogate_refresh_time_in_minutes": desired_location.get("surrogate_refresh_time_in_minutes"),
                    "surrogate_refresh_time_unit": desired_location.get("surrogate_refresh_time_unit"),
                    "ofw_enabled": desired_location.get("ofw_enabled"),
                    "ips_control": desired_location.get("ips_control"),
                    "aup_enabled": desired_location.get("aup_enabled"),
                    "xff_forward_enabled": desired_location.get("xff_forward_enabled"),
                    "caution_enabled": desired_location.get("caution_enabled"),
                    "aup_block_internet_until_accepted": desired_location.get("aup_block_internet_until_accepted"),
                    "aup_force_ssl_inspection": desired_location.get("aup_force_ssl_inspection"),
                    "aup_timeout_in_days": desired_location.get("aup_timeout_in_days"),
                    "profile": desired_location.get("profile"),
                    "geo_override": desired_location.get("geo_override"),
                    "latitude": desired_location.get("latitude"),
                    "longitude": desired_location.get("longitude"),
                    "other_sub_location": desired_location.get("other_sub_location"),
                    "other6_sub_location": desired_location.get("other6_sub_location"),
                    "sub_loc_scope_enabled": desired_location.get("sub_loc_scope_enabled"),
                    "sub_loc_scope": desired_location.get("sub_loc_scope"),
                    "sub_loc_scope_values": desired_location.get("sub_loc_scope_values"),
                    "ipv6_enabled": desired_location.get("ipv6_enabled"),
                    "ipv6_dns64_prefix": desired_location.get("ipv6_dns64_prefix"),
                    "iot_discovery_enabled": desired_location.get("iot_discovery_enabled"),
                    "iot_enforce_policy_set": desired_location.get("iot_enforce_policy_set"),
                    "vpn_credentials": desired_location.get("vpn_credentials"),
                }
            )
            module.warn("Payload Update for SDK: {}".format(create_location))
            new_location, _unused, error = client.locations.add_location(**create_location)
            if error:
                module.fail_json(msg=f"Error creating location: {to_native(error)}")
            module.exit_json(changed=True, data=new_location.as_dict())

    elif state == "absent":
        if existing_location:
            _unused, _unused, error = client.locations.delete_location(location_id=existing_location.get("id"))
            if error:
                module.fail_json(msg=f"Error deleting location: {to_native(error)}")
            module.exit_json(changed=True, data=existing_location)
        else:
            module.exit_json(changed=False, data={})

    module.exit_json(changed=False, data={})


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
        display_time_unit=dict(type="str", required=False, choices=["MINUTE", "HOUR", "DAY"]),
        surrogate_ip_enforced_for_known_browsers=dict(type="bool", required=False),
        surrogate_refresh_time_in_minutes=dict(type="int", required=False),
        surrogate_refresh_time_unit=dict(type="str", required=False, choices=["MINUTE", "HOUR", "DAY"]),
        other_sub_location=dict(type="bool", required=False),
        other6_sub_location=dict(type="bool", required=False),
        sub_loc_scope_enabled=dict(type="bool", required=False),
        sub_loc_scope=dict(
            type="str",
            required=False,
            choices=["VPC_ENDPOINT", "VPC", "NAMESPACE", "ACCOUNT"],
        ),
        sub_loc_scope_values=dict(type="list", elements="str", required=False),
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
