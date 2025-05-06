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
module: zia_cloud_firewall_dns_rules
short_description: "Firewall DNS policy rule."
description: "Adds a new Firewall DNS policy rule."
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
    description: Unique identifier for the Firewall DNS policy rule
    type: int
    required: false
  name:
    description: "Name of the Firewall DNS policy rule"
    required: true
    type: str
  description:
    description: "Additional information about the rule"
    required: false
    type: str
  order:
    description: "Rule order number of the Firewall DNS policy rule"
    required: false
    type: int
  rank:
    description: "Admin rank of the Firewall DNS policy rule"
    required: false
    default: 7
    type: int
  enabled:
    description:
        - Determines whether the Firewall DNS policy rule is enabled or disabled
    required: false
    type: bool
  capture_pcap:
    description:
        - Indicates whether packet capture (PCAP) is enabled or not
    required: false
    type: bool
  locations:
    description: "The locations to which the Firewall DNS policy rule applies"
    type: list
    elements: int
    required: false
  location_groups:
    description: "The location groups to which the Firewall DNS policy rule applies"
    type: list
    elements: int
    required: false
  departments:
    description: "The departments to which the Firewall DNS policy rule applies"
    type: list
    elements: int
    required: false
  groups:
    description: "The groups to which the Firewall DNS policy rule applies"
    type: list
    elements: int
    required: false
  users:
    description: "The users to which the Firewall DNS policy rule applies"
    type: list
    elements: int
    required: false
  time_windows:
    description: "The time interval in which the Firewall DNS policy rule applies"
    type: list
    elements: int
    required: false
  action:
    description: "The action the Firewall DNS policy rule takes when packets match the rule"
    required: false
    type: str
    choices:
        - ALLOW
        - BLOCK
        - REDIR_REQ
        - REDIR_RES
        - REDIR_ZPA
        - REDIR_REQ_DOH
        - REDIR_REQ_KEEP_SENDER
        - REDIR_REQ_TCP
        - REDIR_REQ_UDP
        - BLOCK_WITH_RESPONSE
  block_response_code:
    description:
      - When the action is selected as BLOCK_WITH_RESPONSE to block the DNS traffic
      - Send a response code to the client, specify the response code using this field.
    required: false
    type: str
    choices:
        - FORMERR
        - SERVFAIL
        - NXDOMAIN
        - NOTIMP
        - REFUSED
  protocols:
    description: List of protocols to which this rule applies
    type: list
    elements: str
    required: false
    choices:
      - ANY_RULE
      - SMRULEF_CASCADING_ALLOWED
      - TCP_RULE
      - UDP_RULE
      - DOHTTPS_RULE
  dns_rule_request_types:
    description: DNS request types to which the rule applies
    type: list
    elements: str
    required: false
    choices:
      - A
      - NS
      - MD
      - MF
      - CNAME
      - SOA
      - MB
      - MG
      - MR
      - "NULL"
      - WKS
      - PTR
      - HINFO
      - MINFO
      - MX
      - TXT
      - RP
      - AFSDB
      - X25
      - ISDN
      - RT
      - NSAP
      - NSAP_PTR
      - SIG
      - KEY
      - PX
      - GPOS
      - AAAA
      - LOC
      - NXT
      - EID
      - NIMLOC
      - SRV
      - ATMA
      - NAPTR
      - KX
      - CERT
      - A6
      - DNAME
      - SINK
      - OPT
      - APL
      - DS
      - SSHFP
      - PSECKEF
      - RRSIG
      - NSEC
      - DNSKEY
      - DHCID
      - NSEC3
      - NSEC3PARAM
      - TLSA
      - HIP
      - NINFO
      - RKEY
      - TALINK
      - CDS
      - CDNSKEY
      - OPENPGPKEY
      - CSYNC
      - ZONEMD
      - SVCB
      - HTTPS
  src_ips:
    description:
      - User-defined source IP addresses for which the rule is applicable.
      - If not set, the rule is not restricted to a specific source IP address.
    type: list
    elements: str
    required: false
  src_ip_groups:
    description:
        - User-defined source IP address groups for which the rule is applicable.
        - If not set, the rule is not restricted to a specific source IP address group.
    type: list
    elements: int
    required: false
  dest_addresses:
    description:
      - List of destination IP addresses to which this rule will be applied.
      - CIDR notation can be used for destination IP addresses.
    type: list
    elements: str
    required: false
  dest_ip_categories:
    description:
      - IP address categories of destination for which the DNAT rule is applicable.
      - If not set, the rule is not restricted to specific destination IP categories.
    type: list
    elements: str
    required: false
  dest_countries:
    description:
      - Destination countries for which the rule is applicable.
      - If not set, the rule is not restricted to specific destination countries.
      - Provide a ISO3166 Alpha2 code.  visit the following site for reference U(https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)
    type: list
    elements: str
    required: false
  dest_ip_groups:
    description:
        - User-defined destination IP address groups on which the rule is applied.
        - If not set, the rule is not restricted to a specific destination IP address group.
    type: list
    elements: int
    required: false
  source_countries:
    description:
      - The list of source countries that must be included or excluded from the rule based on the excludeSrcCountries field value.
      - If no value is set, this field is ignored during policy evaluation and the rule is applied to all source countries.
      - Provide a ISO3166 Alpha2 code.  visit the following site for reference U(https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)
    type: list
    elements: str
    required: false
  res_categories:
    description: List of destination domain categories to which the rule applies
    type: list
    elements: str
    required: false
  applications:
    description:
      - User-defined network service applications on which the rule is applied.
      - If not set, the rule is not restricted to a specific network service application.
    type: list
    elements: str
    required: false
  application_groups:
    description:
        - User-defined network service application group on which the rule is applied.
        - If not set, the rule is not restricted to a specific network service application group.
    type: list
    elements: int
    required: false
  labels:
    description: "Labels that are applicable to the rule."
    type: list
    elements: int
    required: false
  dest_ipv6_groups:
    description:
      - Destination IPv6 address groups for which the rule is applicable.
      - If not set, the rule is not restricted to a specific source IPv6 address group.
    type: list
    elements: int
    required: false
  src_ipv6_groups:
    description:
      - Source IPv6 address groups for which the rule is applicable.
      - If not set, the rule is not restricted to a specific source IPv6 address group.
    type: list
    elements: int
    required: false
  dns_gateway:
    description:
        - The DNS gateway used to redirect traffic, specified when the rule action is to redirect DNS request to an external DNS service.
    type: dict
    required: false
    suboptions:
        id:
            description:
                - A unique identifier for an entity
            type: int
            required: false

  zpa_ip_group:
    description:
      - The ZPA IP pool used for domain name resolution when action is REDIR_ZPA.
    type: dict
    required: false
    suboptions:
      id:
        description: Unique identifier of the ZPA IP group.
        type: int
        required: false
      name:
        description: Name of the ZPA IP group.
        type: str
        required: false
"""

EXAMPLES = r"""
- name: Create/update  Firewall DNS rule
  zscaler.ziacloud.zia_cloud_firewall_filtering_rule:
    provider: '{{ provider }}'
    state: present
    name: "Ansible_Example_Rule"
    description: "TT#1965232865"
    action: "ALLOW"
    enabled: true
    order: 1
    source_countries:
      - BR
      - CA
      - US
    dest_countries:
      - BR
      - CA
      - US
"""

RETURN = r"""
# Returns information on the newly created cloud Firewall DNS rule.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
    validate_iso3166_alpha2,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_rule(rule):
    """
    Normalize rule data by removing computed values.
    """
    if not rule:
        return {}

    normalized = rule.copy()
    computed_values = []
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def validate_action_requirements(
    module, action, dns_gateway, redirect_ip, block_response_code
):
    if action in ["ALLOW", "BLOCK", "BLOCK_WITH_RESPONSE", "REDIR_RES"]:
        if dns_gateway:
            module.fail_json(
                msg=f"The action '{action}' is not compatible with 'dns_gateway'. This attribute should only be set with REDIR_REQ_* actions."
            )

    if action == "REDIR_RES" and not redirect_ip:
        module.fail_json(
            msg="When 'action' is set to 'REDIR_RES', the 'redirect_ip' must be provided."
        )

    if action == "BLOCK_WITH_RESPONSE" and not block_response_code:
        module.fail_json(
            msg="When 'action' is set to 'BLOCK_WITH_RESPONSE', the 'block_response_code' must be provided."
        )

    if action == "REDIR_REQ_KEEP_SENDER" and not dns_gateway:
        module.fail_json(
            msg="When 'action' is set to 'REDIR_REQ_KEEP_SENDER', the 'dns_gateway' must be provided."
        )


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)

    params = [
        "id",
        "name",
        "description",
        "order",
        "rank",
        "locations",
        "location_groups",
        "departments",
        "groups",
        "users",
        "time_windows",
        "action",
        "enabled",
        "capture_pcap",
        "block_response_code",
        "dns_rule_request_types",
        "redirect_ip",
        "applications",
        "protocols",
        "src_ips",
        "src_ip_groups",
        "src_ipv6_groups",
        "dest_addresses",
        "dest_ip_categories",
        "dest_countries",
        "source_countries",
        "application_groups",
        "dest_ip_groups",
        "dest_ipv6_groups",
        "dns_gateway",
        "zpa_ip_group",
        "labels",
        "res_categories",
        "edns_ecs_object",
    ]

    rule = {
        param: module.params.get(param)
        for param in params
        if module.params.get(param) is not None
    }

    # Validate and format country codes
    source_countries = rule.get("source_countries")
    if source_countries:
        validated_source_countries = []
        for country_code in source_countries:
            if validate_iso3166_alpha2(country_code):
                validated_source_countries.append(f"COUNTRY_{country_code}")
            else:
                module.fail_json(
                    msg=(
                        f"The source country code '{country_code}' is not a valid ISO3166 Alpha2 code. "
                        "Please visit the following site for reference: "
                        "https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes"
                    )
                )
        rule["source_countries"] = validated_source_countries

    dest_countries = rule.get("dest_countries")
    if dest_countries:
        validated_dest_countries = []
        for country_code in dest_countries:
            if validate_iso3166_alpha2(country_code):
                validated_dest_countries.append(f"COUNTRY_{country_code}")
            else:
                module.fail_json(
                    msg=(
                        f"The destination country code '{country_code}' is not a valid ISO3166 Alpha2 code. "
                        "Please visit the following site for reference: "
                        "https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes"
                    )
                )
        rule["dest_countries"] = validated_dest_countries

    # Preprocess specific attributes
    def preprocess_attributes(rule):
        # Normalize dns_gateway by retaining only the 'id'
        if isinstance(rule.get("dns_gateway"), dict):
            dns_gateway_id = rule["dns_gateway"].get("id")
            rule["dns_gateway"] = {"id": dns_gateway_id} if dns_gateway_id else None

        # Normalize zpa_ip_group by retaining only the 'id'
        if isinstance(rule.get("zpa_ip_group"), dict):
            zpa_id = rule["zpa_ip_group"].get("id")
            rule["zpa_ip_group"] = {"id": zpa_id} if zpa_id else None

    preprocess_attributes(rule)

    validate_action_requirements(
        module,
        rule.get("action"),
        rule.get("dns_gateway"),
        rule.get("redirect_ip"),
        rule.get("block_response_code"),
    )

    rule_id = rule.get("id")
    rule_name = rule.get("name")

    existing_rule = None
    if rule_id is not None:
        result, _unused, error = client.cloud_firewall_dns.get_rule(rule_id=rule_id)
        if error:
            module.fail_json(
                msg=f"Error fetching rule with id {rule_id}: {to_native(error)}"
            )
        if result:
            existing_rule = result.as_dict()
    else:
        result, _unused, error = client.cloud_firewall_dns.list_rules()
        if error:
            module.fail_json(msg=f"Error listing rules: {to_native(error)}")
        if result:
            for rule_ in result:
                if rule_.name == rule_name:
                    existing_rule = rule_.as_dict()
                    break

    # Handle predefined/default rules
    if (
        state == "absent"
        and existing_rule
        and (
            existing_rule.get("default_rule", False)
            or existing_rule.get("predefined", False)
        )
    ):
        module.exit_json(
            changed=False, msg="Deletion of default or predefined rule is not allowed."
        )

    # Normalize and compare rules
    desired_rule = normalize_rule(rule)
    current_rule = normalize_rule(existing_rule) if existing_rule else {}

    def preprocess_rule(rule_dict, params):
        """Preprocess rule attributes for comparison."""
        processed = rule_dict.copy()
        for attr in params:
            if attr in processed and processed[attr] is not None:
                # Handle dictionary-based references like dns_gateway or zpa_ip_group
                if isinstance(processed[attr], dict) and "id" in processed[attr]:
                    processed[attr] = {"id": processed[attr]["id"]}
                elif isinstance(processed[attr], list):
                    if all(
                        isinstance(item, dict) and "id" in item
                        for item in processed[attr]
                    ):
                        processed[attr] = [item["id"] for item in processed[attr]]
                    else:
                        processed[attr] = sorted(processed[attr])
        return processed

    desired_processed = preprocess_rule(desired_rule, params)
    current_processed = preprocess_rule(current_rule, params)

    # List of attributes where empty list and None should be treated as equivalent
    list_attributes = [
        "locations",
        "location_groups",
        "departments",
        "groups",
        "users",
        "time_windows",
        "dns_rule_request_types",
        "applications",
        "protocols",
        "src_ips",
        "src_ip_groups",
        "src_ipv6_groups",
        "dest_addresses",
        "dest_ip_categories",
        "dest_countries",
        "source_countries",
        "application_groups",
        "dest_ip_groups",
        "dest_ipv6_groups",
        "dns_gateway",
        "zpa_ip_group",
        "labels",
        "res_categories",
        "edns_ecs_object",
    ]

    differences_detected = False
    for key in params:
        desired_value = desired_processed.get(key)
        current_value = current_processed.get(key)

        # Skip ID comparison if not in desired rule
        if key == "id" and desired_value is None and current_value is not None:
            continue

        # Convert state to enabled boolean
        if key == "enabled" and "state" in current_rule:
            current_value = current_rule["state"] == "ENABLED"

        # Handle list attributes - treat None and [] as equivalent
        if key in list_attributes:
            if desired_value in (None, []) and current_value in (None, []):
                continue
            if desired_value is None:
                desired_value = []
            if current_value is None:
                current_value = []

        # Sort lists of IDs for comparison
        if isinstance(desired_value, list) and isinstance(current_value, list):
            if all(isinstance(x, int) for x in desired_value) and all(
                isinstance(x, int) for x in current_value
            ):
                desired_value = sorted(desired_value)
                current_value = sorted(current_value)

        if current_value != desired_value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
            )

    if module.check_mode:
        module.exit_json(
            changed=bool(
                (state == "present" and (not existing_rule or differences_detected))
                or (state == "absent" and existing_rule)
            )
        )

    if state == "present":
        if existing_rule:
            if differences_detected:
                update_data = deleteNone(
                    {
                        "rule_id": existing_rule.get("id"),
                        "name": desired_rule.get("name"),
                        "order": desired_rule.get("order"),
                        "rank": desired_rule.get("rank"),
                        "action": desired_rule.get("action"),
                        "enabled": desired_rule.get("enabled"),
                        "description": desired_rule.get("description"),
                        "capture_pcap": desired_rule.get("capture_pcap"),
                        "src_ips": desired_rule.get("src_ips"),
                        "dest_addresses": desired_rule.get("dest_addresses"),
                        "dest_ip_categories": desired_rule.get("dest_ip_categories"),
                        "dest_countries": desired_rule.get("dest_countries"),
                        "res_categories": desired_rule.get("res_categories"),
                        "source_countries": desired_rule.get("source_countries"),
                        "dest_ip_groups": desired_rule.get("dest_ip_groups"),
                        "dest_ipv6_groups": desired_rule.get("dest_ipv6_groups"),
                        "dns_gateway": desired_rule.get("dns_gateway"),
                        "edns_ecs_object": desired_rule.get("edns_ecs_object"),
                        "zpa_ip_group": desired_rule.get("zpa_ip_group"),
                        "labels": desired_rule.get("labels"),
                        "locations": desired_rule.get("locations"),
                        "location_groups": desired_rule.get("location_groups"),
                        "departments": desired_rule.get("departments"),
                        "groups": desired_rule.get("groups"),
                        "users": desired_rule.get("users"),
                        "time_windows": desired_rule.get("time_windows"),
                        "src_ip_groups": desired_rule.get("src_ip_groups"),
                        "src_ipv6_groups": desired_rule.get("src_ipv6_groups"),
                        "applications": desired_rule.get("applications"),
                        "application_groups": desired_rule.get("application_groups"),
                        "protocols": desired_rule.get("protocols"),
                        "dns_rule_request_types": desired_rule.get(
                            "dns_rule_request_types"
                        ),
                        "redirect_ip": desired_rule.get("redirect_ip"),
                        "block_response_code": desired_rule.get("block_response_code"),
                    }
                )
                module.warn("Payload Update for SDK: {}".format(update_data))
                updated_rule, _unused, error = client.cloud_firewall_dns.update_rule(
                    **update_data
                )
                if error:
                    module.fail_json(msg=f"Error updating rule: {to_native(error)}")
                module.exit_json(changed=True, data=updated_rule.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule)
        else:
            create_data = deleteNone(
                {
                    "name": desired_rule.get("name"),
                    "order": desired_rule.get("order"),
                    "rank": desired_rule.get("rank"),
                    "action": desired_rule.get("action"),
                    "enabled": desired_rule.get("enabled"),
                    "description": desired_rule.get("description"),
                    "capture_pcap": desired_rule.get("capture_pcap"),
                    "src_ips": desired_rule.get("src_ips"),
                    "dest_addresses": desired_rule.get("dest_addresses"),
                    "dest_ip_categories": desired_rule.get("dest_ip_categories"),
                    "dest_countries": desired_rule.get("dest_countries"),
                    "res_categories": desired_rule.get("res_categories"),
                    "source_countries": desired_rule.get("source_countries"),
                    "dest_ip_groups": desired_rule.get("dest_ip_groups"),
                    "dest_ipv6_groups": desired_rule.get("dest_ipv6_groups"),
                    "dns_gateway": desired_rule.get("dns_gateway"),
                    "edns_ecs_object": desired_rule.get("edns_ecs_object"),
                    "zpa_ip_group": desired_rule.get("zpa_ip_group"),
                    "labels": desired_rule.get("labels"),
                    "locations": desired_rule.get("locations"),
                    "location_groups": desired_rule.get("location_groups"),
                    "departments": desired_rule.get("departments"),
                    "groups": desired_rule.get("groups"),
                    "users": desired_rule.get("users"),
                    "time_windows": desired_rule.get("time_windows"),
                    "src_ip_groups": desired_rule.get("src_ip_groups"),
                    "src_ipv6_groups": desired_rule.get("src_ipv6_groups"),
                    "applications": desired_rule.get("applications"),
                    "application_groups": desired_rule.get("application_groups"),
                    "protocols": desired_rule.get("protocols"),
                    "dns_rule_request_types": desired_rule.get(
                        "dns_rule_request_types"
                    ),
                    "redirect_ip": desired_rule.get("redirect_ip"),
                    "block_response_code": desired_rule.get("block_response_code"),
                }
            )
            module.warn("Payload Update for SDK: {}".format(create_data))
            new_rule, _unused, error = client.cloud_firewall_dns.add_rule(**create_data)
            if error:
                module.fail_json(msg=f"Error creating rule: {to_native(error)}")
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            _unused, _unused, error = client.cloud_firewall_dns.delete_rule(
                rule_id=existing_rule.get("id")
            )
            if error:
                module.fail_json(msg=f"Error deleting rule: {to_native(error)}")
            module.exit_json(changed=True, data=existing_rule)
        else:
            module.exit_json(changed=False, data={})

    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    id_spec = dict(
        type="list",
        elements="int",
        required=False,
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        enabled=dict(type="bool", required=False),
        order=dict(type="int", required=False),
        rank=dict(type="int", required=False, default=7),
        src_ips=dict(type="list", elements="str", required=False),
        dns_rule_request_types=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "A",
                "NS",
                "MD",
                "MF",
                "CNAME",
                "SOA",
                "MB",
                "MG",
                "MR",
                "NULL",
                "WKS",
                "PTR",
                "HINFO",
                "MINFO",
                "MX",
                "TXT",
                "RP",
                "AFSDB",
                "X25",
                "ISDN",
                "RT",
                "NSAP",
                "NSAP_PTR",
                "SIG",
                "KEY",
                "PX",
                "GPOS",
                "AAAA",
                "LOC",
                "NXT",
                "EID",
                "NIMLOC",
                "SRV",
                "ATMA",
                "NAPTR",
                "KX",
                "CERT",
                "A6",
                "DNAME",
                "SINK",
                "OPT",
                "APL",
                "DS",
                "SSHFP",
                "PSECKEF",
                "RRSIG",
                "NSEC",
                "DNSKEY",
                "DHCID",
                "NSEC3",
                "NSEC3PARAM",
                "TLSA",
                "HIP",
                "NINFO",
                "RKEY",
                "TALINK",
                "CDS",
                "CDNSKEY",
                "OPENPGPKEY",
                "CSYNC",
                "ZONEMD",
                "SVCB",
                "HTTPS",
            ],
        ),
        applications=dict(type="list", elements="str", required=False),
        protocols=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "ANY_RULE",
                "SMRULEF_CASCADING_ALLOWED",
                "TCP_RULE",
                "UDP_RULE",
                "DOHTTPS_RULE",
            ],
        ),
        dest_addresses=dict(type="list", elements="str", required=False),
        dest_ip_categories=dict(type="list", elements="str", required=False),
        dest_countries=dict(type="list", elements="str", required=False),
        source_countries=dict(type="list", elements="str", required=False),
        res_categories=dict(type="list", elements="str", required=False),
        capture_pcap=dict(type="bool", required=False),
        block_response_code=dict(
            type="str",
            required=False,
            choices=["FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"],
        ),
        action=dict(
            type="str",
            required=False,
            choices=[
                "ALLOW",
                "BLOCK",
                "REDIR_REQ",
                "REDIR_RES",
                "REDIR_ZPA",
                "REDIR_REQ_DOH",
                "REDIR_REQ_KEEP_SENDER",
                "REDIR_REQ_TCP",
                "REDIR_REQ_UDP",
                "BLOCK_WITH_RESPONSE",
            ],
        ),
        dns_gateway=dict(
            type="dict",
            required=False,
            options=dict(
                id=dict(type="int", required=False),
            ),
        ),
        zpa_ip_group=dict(
            type="dict",
            required=False,
            options=dict(
                id=dict(type="int", required=False),
                name=dict(type="str", required=False),
            ),
        ),
        application_groups=id_spec,
        dest_ip_groups=id_spec,
        dest_ipv6_groups=id_spec,
        labels=id_spec,
        locations=id_spec,
        location_groups=id_spec,
        departments=id_spec,
        groups=id_spec,
        users=id_spec,
        time_windows=id_spec,
        src_ip_groups=id_spec,
        src_ipv6_groups=id_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
