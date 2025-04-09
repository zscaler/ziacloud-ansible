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
module: zia_location_management_info
short_description: "Gets locations only, not sub-locations."
description:
  - "Gets locations only, not sub-locations."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  id:
    description: "The unique identifier for the location"
    type: int
    required: false
  name:
    description: "The location name"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all ZIA Locations
  zscaler.ziacloud.zia_location_management_info:
    provider: '{{ provider }}'

- name: Gather Information Details of ZIA Location By Name
  zscaler.ziacloud.zia_location_management_info:
    provider: '{{ provider }}'
    name: "USA-SJC37"
"""

RETURN = r"""
locations:
  description: A list of ZIA locations with detailed configuration settings.
  returned: always
  type: list
  elements: dict
  contains:
    aup_block_internet_until_accepted:
      description: Specifies if Internet access is blocked until the Acceptable Use Policy (AUP) is accepted.
      returned: always
      type: bool
      sample: false
    aup_enabled:
      description: Indicates if Acceptable Use Policy (AUP) is enabled for the location.
      returned: always
      type: bool
      sample: false
    aup_force_ssl_inspection:
      description: Indicates if SSL inspection is enforced when AUP is enabled.
      returned: always
      type: bool
      sample: false
    aup_timeout_in_days:
      description: The number of days before the AUP acceptance is timed out.
      returned: always
      type: int
      sample: 0
    auth_required:
      description: Indicates if authentication is required for this location.
      returned: always
      type: bool
      sample: true
    caution_enabled:
      description: Indicates if caution is enabled for this location.
      returned: always
      type: bool
      sample: false
    child_count:
      description: The count of child locations under this location.
      returned: always
      type: int
      sample: 0
    cookies_and_proxy:
      description: Indicates if cookies and proxy are used for this location.
      returned: always
      type: bool
      sample: false
    country:
      description: The country where the location is based.
      returned: always
      type: str
      sample: "CANADA"
    description:
      description: A description of the location.
      returned: always
      type: str
      sample: "SJC_Location37"
    digest_auth_enabled:
      description: Indicates if digest authentication is enabled for this location.
      returned: always
      type: bool
      sample: false
    display_time_unit:
      description: The unit of time used to display time-related settings.
      returned: always
      type: str
      sample: "HOUR"
    dn_bandwidth:
      description: The downstream bandwidth for this location in Mbps.
      returned: always
      type: int
      sample: 10000
    dynamiclocation_groups:
      description: A list of dynamic location groups associated with this location.
      returned: always
      type: list
      elements: dict
      contains:
        id:
          description: The ID of the dynamic location group.
          type: int
          sample: 44772848
        name:
          description: The name of the dynamic location group.
          type: str
          sample: "Corporate User Traffic Group"
    ec_location:
      description: Indicates if this is an EC location.
      returned: always
      type: bool
      sample: false
    exclude_from_dynamic_groups:
      description: Indicates if this location is excluded from dynamic groups.
      returned: always
      type: bool
      sample: false
    exclude_from_manual_groups:
      description: Indicates if this location is excluded from manual groups.
      returned: always
      type: bool
      sample: false
    geo_override:
      description: Indicates if geography override is enabled for this location.
      returned: always
      type: bool
      sample: false
    id:
      description: The ID of the location.
      returned: always
      type: str
      sample: "108668017"
    idle_time_in_minutes:
      description: The idle time in minutes before a session is considered inactive.
      returned: always
      type: int
      sample: 480
    ip_addresses:
      description: A list of IP addresses associated with this location.
      returned: always
      type: list
      elements: str
      sample: ["200.201.200.2"]
    ips_control:
      description: Indicates if IPS control is enabled for this location.
      returned: always
      type: bool
      sample: true
    name:
      description: The name of the location.
      returned: always
      type: str
      sample: "USA-SJC37"
    ofw_enabled:
      description: Indicates if OFW (On-the-Fly Whitelisting) is enabled for this location.
      returned: always
      type: bool
      sample: true
    profile:
      description: The profile assigned to this location.
      returned: always
      type: str
      sample: "CORPORATE"
    ssl_scan_enabled:
      description: Indicates if SSL scanning is enabled for this location.
      returned: always
      type: bool
      sample: false
    state:
      description: The state or province of the location.
      returned: always
      type: str
      sample: "British Columbia"
    tz:
      description: The timezone in which the location operates.
      returned: always
      type: str
      sample: "CANADA_AMERICA_VANCOUVER"
    up_bandwidth:
      description: The upstream bandwidth for this location in Mbps.
      returned: always
      type: int
      sample: 10000
    xff_forward_enabled:
      description: Indicates if X-Forwarded-For header forwarding is enabled.
      returned: always
      type: bool
      sample: true
"""


from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper


def core(module):
    location_id = module.params.get("id")
    location_name = module.params.get("name")

    client = ZIAClientHelper(module)
    locations = []

    if location_id is not None:
        location_obj, _, error = client.locations.get_location(location_id)
        if error or location_obj is None:
            module.fail_json(msg=f"Failed to retrieve location with ID '{location_id}': {to_native(error)}")
        locations = [location_obj.as_dict()]
    else:
        # ✅ Collect all parameters into query_params
        query_params = {}
        if location_name:
            query_params["search"] = location_name

        for param in [
            "ssl_scan_enabled", "xff_enabled",
            "auth_required", "bw_enforced", "enable_iot"
        ]:
            val = module.params.get(param)
            if val is not None:
                query_params[param] = val

        result, _, error = client.locations.list_locations(query_params=query_params)
        if error:
            module.fail_json(msg=f"Error retrieving locations: {to_native(error)}")

        locations = [l.as_dict() for l in result] if result else []

    module.exit_json(changed=False, locations=locations)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
        ssl_scan_enabled=dict(type="bool", required=False),
        xff_enabled=dict(type="bool", required=False),
        auth_required=dict(type="bool", required=False),
        bw_enforced=dict(type="bool", required=False),
        enable_iot=dict(type="bool", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        mutually_exclusive=[["id", "name"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
