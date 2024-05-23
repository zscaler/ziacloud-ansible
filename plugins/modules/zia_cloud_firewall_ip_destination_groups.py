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
module: zia_cloud_firewall_ip_destination_groups
short_description: "Create IP destination groups."
description:
  - "This module allows you to create IP destination groups within the Zscaler Internet Access (ZIA) Cloud firewall."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description: "Unique identifier for the destination IP group."
    required: false
    type: int
  name:
    description: "Destination IP group name."
    required: true
    type: str
  description:
    description: "Additional information about the destination IP group."
    required: false
    type: str
  type:
    description: "Destination IP group type (i.e., the group can contain destination IP addresses or FQDNs)."
    required: false
    type: str
    choices:
      - DSTN_IP
      - DSTN_FQDN
      - DSTN_DOMAIN
      - DSTN_OTHER
  addresses:
    description: "Destination IP addresses, FQDNs, or wildcard FQDNs added to the group."
    type: list
    elements: str
    required: false
  ip_categories:
    description:
      - Destination IP address URL categories.
      - You can identify destinations based on the URL category of the domain.
      - There are hundreds of categories available such as ANY, NONE, SOCIAL_ADULT, OTHER_BUSINESS_AND_ECONOMY, etc.
      - Visit for choices U(https://help.zscaler.com/zia/firewall-policies#/ipDestinationGroups-get).
    type: list
    elements: str
    required: false
  countries:
    description:
      - This option is available only when the attribute type is set to DSTN_OTHER
      - Destination IP address countries.
      - You can identify destinations based on the location of a server.
      - Supports 2-letter ISO3166 Alpha2 Country i.e BR, CA, US.
      - Please visit the following site for reference U(https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)
    type: list
    elements: str
    required: false
  url_categories:
    description:
      - This option is available only when the attribute type is set to DSTN_OTHER
      - To identify destinations based on the URL category of a domain, select the required URL categories.
      - If no category is selected, the field remains set to Any, and the criteria will be ignored during policy evaluation.
      - Only custom URL categories are supported
    type: list
    elements: str
    required: false
"""

EXAMPLES = r"""
- name: Create/Update/Delete ip destination group - DSTN_FQDN.
  zscaler.ziacloud.zia_cloud_firewall_ip_destination_groups:
    provider: '{{ provider }}'
    name: "Example"
    description: "Example"
    type: "DSTN_FQDN"
    addresses: ["test1.acme.com", "test2.acme.com", "test3.acme.com"]

- name: Create/Update/Delete ip destination group - DSTN_IP by Country.
  zscaler.ziacloud.zia_cloud_firewall_ip_destination_groups:
    provider: '{{ provider }}'
    name: "example"
    description: "example"
    type: "DSTN_IP"
    addresses: ["1.2.3.4", "1.2.3.5", "1.2.3.6"]
    countries: ["COUNTRY_CA"]

- name: Create/Update/Delete ip destination group - DSTN_IP.
  zscaler.ziacloud.zia_cloud_firewall_ip_destination_groups:
    provider: '{{ provider }}'
    name: "Example - IP Ranges"
    description: "Example - IP Ranges"
    type: "DSTN_IP"
    addresses:
      - "3.217.228.0-3.217.231.255"
      - "3.235.112.0-3.235.119.255"
      - "52.23.61.0-52.23.62.25"
      - "35.80.88.0-35.80.95.255"
"""

RETURN = r"""
# The newly created ip destination group resource record.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    validate_iso3166_alpha2,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_ip_group(group):
    """
    Normalize ip destination group data by setting computed values and sorting lists.
    """
    normalized = group.copy()

    computed_values = [
        "id",
        "creation_time",
        "modified_by",
        "modified_time",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    # Sort the addresses list to ensure order is ignored during comparison
    if "addresses" in normalized and normalized["addresses"]:
        normalized["addresses"] = sorted(normalized["addresses"])

    # Convert None values for lists to empty lists for comparison purposes
    list_fields = ["ip_categories", "url_categories", "countries"]
    for field in list_fields:
        if normalized.get(field) is None:
            normalized[field] = []

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    destination_group = {}
    params = [
        "id",
        "name",
        "description",
        "type",
        "addresses",
        "ip_categories",
        "url_categories",
        "countries",
    ]
    for param_name in params:
        destination_group[param_name] = module.params.get(param_name)

    # Perform validation and prepending 'COUNTRY_' for countries list
    countries = destination_group.get("countries")
    if countries:
        validated_countries = []
        for country_code in countries:
            if validate_iso3166_alpha2(country_code):
                validated_countries.append(f"COUNTRY_{country_code}")
            else:
                module.fail_json(
                    msg=f"The country code '{country_code}' is not a valid ISO3166 Alpha2 code."
                )
        destination_group["countries"] = validated_countries

    # Now that destination_group is populated, perform the conditional validation check
    destination_type = destination_group["type"]
    ip_categories = destination_group["ip_categories"]
    countries = destination_group["countries"]

    # Check if the type is DSTN_OTHER, then either ip_categories or countries should be set
    if destination_type == "DSTN_OTHER" and not (ip_categories or countries):
        module.fail_json(
            msg="'ip_categories' or 'countries' must be set when 'type' is 'DSTN_OTHER'."
        )

    group_id = destination_group.get("id", None)
    group_name = destination_group.get("name", None)
    existing_dest_ip_group = None

    if group_id is not None:
        existing_dest_ip_group = client.firewall.get_ip_destination_group(
            group_id
        ).to_dict()
    else:
        dest_groups = client.firewall.list_ip_destination_groups().to_list()
        if group_name is not None:
            for ip in dest_groups:
                if ip.get("name", None) == group_name:
                    existing_dest_ip_group = ip
                    break

    # Normalize and compare existing and desired data
    normalized_group = normalize_ip_group(destination_group)
    normalized_existing_group = (
        normalize_ip_group(existing_dest_ip_group) if existing_dest_ip_group else {}
    )

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in normalized_group.items():
        if key not in fields_to_exclude and normalized_existing_group.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing_group.get(key)}, Desired: {value}"
            )

    if existing_dest_ip_group is not None:
        id = existing_dest_ip_group.get("id")
        existing_dest_ip_group.update(normalized_group)
        existing_dest_ip_group["id"] = id

    if state == "present":
        if existing_dest_ip_group is not None:
            if differences_detected:
                """Update"""
                existing_dest_ip_group = client.firewall.update_ip_destination_group(
                    group_id=existing_dest_ip_group.get("id", ""),
                    name=existing_dest_ip_group.get("name", ""),
                    type=existing_dest_ip_group.get("type", ""),
                    addresses=existing_dest_ip_group.get("addresses", ""),
                    description=existing_dest_ip_group.get("description", ""),
                    ip_categories=existing_dest_ip_group.get("ip_categories", ""),
                    url_categories=existing_dest_ip_group.get("url_categories", ""),
                    countries=existing_dest_ip_group.get("countries", ""),
                ).to_dict()
                module.exit_json(changed=True, data=existing_dest_ip_group)
        else:
            """Create"""
            destination_group = client.firewall.add_ip_destination_group(
                name=destination_group.get("name", ""),
                type=destination_group.get("type", ""),
                addresses=destination_group.get("addresses", ""),
                description=destination_group.get("description", ""),
                ip_categories=destination_group.get("ip_categories", ""),
                url_categories=destination_group.get("url_categories", ""),
                countries=destination_group.get("countries", ""),
            ).to_dict()
            module.exit_json(changed=False, data=destination_group)
    elif state == "absent":
        if existing_dest_ip_group is not None:
            code = client.firewall.delete_ip_destination_group(
                existing_dest_ip_group.get("id")
            )
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_dest_ip_group)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        type=dict(
            type="str",
            required=False,
            choices=["DSTN_IP", "DSTN_FQDN", "DSTN_DOMAIN", "DSTN_OTHER"],
        ),
        addresses=dict(type="list", elements="str", required=False),
        ip_categories=dict(type="list", elements="str", required=False),
        url_categories=dict(type="list", elements="str", required=False),
        countries=dict(type="list", elements="str", required=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
