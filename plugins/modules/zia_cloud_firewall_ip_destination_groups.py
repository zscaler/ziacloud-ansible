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
notes:
    - Check mode is supported.
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

    computed_values = ["id", "creation_time", "modified_by", "modified_time"]
    for attr in computed_values:
        normalized.pop(attr, None)

    if "addresses" in normalized and normalized["addresses"]:
        normalized["addresses"] = sorted(normalized["addresses"])

    list_fields = ["ip_categories", "url_categories", "countries"]
    for field in list_fields:
        if normalized.get(field) is None:
            normalized[field] = []

    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    destination_group = {
        p: module.params.get(p)
        for p in [
            "id",
            "name",
            "description",
            "type",
            "addresses",
            "ip_categories",
            "url_categories",
            "countries",
        ]
    }

    # Validate countries and convert to COUNTRY_ prefix
    countries = destination_group.get("countries")
    if countries:
        validated = []
        for code in countries:
            if validate_iso3166_alpha2(code):
                validated.append(f"COUNTRY_{code}")
            else:
                module.fail_json(msg=f"The country code '{code}' is not valid.")
        destination_group["countries"] = validated

    # If type is DSTN_OTHER, either ip_categories or countries must be provided
    if destination_group["type"] == "DSTN_OTHER" and not (
        destination_group.get("ip_categories") or destination_group.get("countries")
    ):
        module.fail_json(
            msg="'ip_categories' or 'countries' must be set when 'type' is 'DSTN_OTHER'."
        )

    group_id = destination_group.get("id")
    group_name = destination_group.get("name")
    existing_group = None

    if group_id:
        result, _unused, error = client.cloud_firewall.get_ip_destination_group(
            group_id
        )
        if error:
            module.fail_json(
                msg=f"Error retrieving group with ID {group_id}: {to_native(error)}"
            )
        existing_group = result.as_dict()
    else:
        result, _unused, error = client.cloud_firewall.list_ip_destination_groups()
        if error:
            module.fail_json(msg=f"Error listing groups: {to_native(error)}")
        all_groups = [g.as_dict() for g in result]
        for g in all_groups:
            if g.get("name") == group_name:
                existing_group = g
                break

    normalized_desired = normalize_ip_group(destination_group)
    normalized_existing = normalize_ip_group(existing_group) if existing_group else {}

    differences_detected = any(
        normalized_desired[k] != normalized_existing.get(k)
        for k in normalized_desired
        if k != "id"
    )

    if module.check_mode:
        if state == "present" and (existing_group is None or differences_detected):
            module.exit_json(changed=True)
        if state == "absent" and existing_group:
            module.exit_json(changed=True)
        module.exit_json(changed=False)

    if existing_group:
        existing_group.update(normalized_desired)
        existing_group["id"] = existing_group.get("id") or group_id

    if state == "present":
        if existing_group:
            if differences_detected:
                group_id_to_update = existing_group.get("id")
                if not group_id_to_update:
                    module.fail_json(
                        msg="Cannot update destination group: ID is missing."
                    )

                updated_group, _unused, error = (
                    client.cloud_firewall.update_ip_destination_group(
                        group_id=group_id_to_update,
                        name=destination_group.get("name"),
                        type=destination_group.get("type"),
                        addresses=destination_group.get("addresses", []),
                        description=destination_group.get("description", ""),
                        ip_categories=destination_group.get("ip_categories", []),
                        url_categories=destination_group.get("url_categories", []),
                        countries=destination_group.get("countries", []),
                    )
                )
                if error:
                    module.fail_json(msg=f"Error updating group: {to_native(error)}")
                module.exit_json(changed=True, data=updated_group.as_dict())
            else:
                module.exit_json(changed=False, data=existing_group)
        else:
            new_group, _unused, error = client.cloud_firewall.add_ip_destination_group(
                name=destination_group["name"],
                type=destination_group["type"],
                addresses=destination_group.get("addresses", []),
                description=destination_group.get("description", ""),
                ip_categories=destination_group.get("ip_categories", []),
                url_categories=destination_group.get("url_categories", []),
                countries=destination_group.get("countries", []),
            )
            if error:
                module.fail_json(msg=f"Error creating group: {to_native(error)}")
            module.exit_json(changed=True, data=new_group.as_dict())

    elif state == "absent":
        if existing_group:
            group_id_to_delete = existing_group.get("id")
            if not group_id_to_delete:
                module.fail_json(msg="Cannot delete destination group: ID is missing.")
            _unused, _unused, error = client.cloud_firewall.delete_ip_destination_group(
                group_id_to_delete
            )
            if error:
                module.fail_json(msg=f"Error deleting group: {to_native(error)}")
            module.exit_json(changed=True, data=existing_group)
        else:
            module.exit_json(changed=False, data={})

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
