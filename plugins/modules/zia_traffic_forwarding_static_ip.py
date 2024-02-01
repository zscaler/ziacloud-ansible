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

DOCUMENTATION = r"""
---
module: zia_traffic_forwarding_static_ip
short_description: "Adds a static IP address."
description:
  - "Adds a static IP address."
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
    description: ""
    type: int
    required: False
  ip_address:
    description:
      - The static IP address
    required: True
    type: str
  routable_ip:
    description:
      - Indicates whether a non-RFC 1918 IP address is publicly routable.
      - This attribute is ignored if there is no ZIA Private Service Edge associated to the organization."
    required: False
    type: bool
  comment:
    description:
      - Additional information about this static IP address
    required: False
    type: str
  geo_override:
    description:
      - If not set, geographic coordinates and city are automatically determined from the IP address.
      - Otherwise, the latitude and longitude coordinates must be provided.
    required: False
    type: bool
  latitude:
    description:
      - Required only if the geoOverride attribute is set.
      - Latitude with 7 digit precision after decimal point, ranges between -90 and 90 degrees.
    required: False
    type: int
  longitude:
    description:
      - Required only if the geoOverride attribute is set.
      - Longitude with 7 digit precision after decimal point, ranges between -180 and 180 degrees.
    required: False
    type: int
  state:
    description:
      - Whether the app connector group should be present or absent.
    type: str
    choices:
      - present
      - absent
    default: present
"""

EXAMPLES = r"""
- name: Create/Update/Delete a Static IP.
  zscaler.ziacloud.zia_traffic_forwarding_static_ip:
    provider: '{{ provider }}'
    ip_address: "1.1.1.1"
    routable_ip: true
    comment: "Created with Ansible"
    geo_override: true
    latitude: "-36.848461"
    longitude: "174.763336"
"""

RETURN = r"""
# The newly created static ip resource record.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
    validate_latitude,
    validate_longitude,
    diff_suppress_func_coordinate,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_static_ip(static):
    """
    Normalize static ip data by setting computed values.
    """
    normalized = static.copy()

    computed_values = ["id"]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    static_ip = dict()
    params = [
        "id",
        "ip_address",
        "geo_override",
        "latitude",
        "longitude",
        "routable_ip",
        "comment",
    ]
    for param_name in params:
        static_ip[param_name] = module.params.get(param_name, None)

    if static_ip.get("geo_override") and (
        static_ip.get("latitude") is None or static_ip.get("longitude") is None
    ):
        module.fail_json(
            msg="When 'geo_override' is set to True, 'latitude' and 'longitude' must be provided."
        )

    # Validate latitude and longitude if provided
    latitude = static_ip.get("latitude")
    longitude = static_ip.get("longitude")

    if latitude is not None and longitude is not None:
        _, lat_errors = validate_latitude(latitude)
        _, lon_errors = validate_longitude(longitude)
        if lat_errors:
            module.fail_json(msg="; ".join(lat_errors))
        if lon_errors:
            module.fail_json(msg="; ".join(lon_errors))

    static_ip_id = static_ip.get("id", None)
    ip_address = static_ip.get("ip_address", None)
    existing_static_ip = None
    if static_ip_id is not None:
        existing_static_ip = client.traffic.get_static_ip(static_ip_id).to_dict()
    else:
        static_ips = client.traffic.list_static_ips().to_list()
        if ip_address is not None:
            for ip in static_ips:
                if ip.get("ip_address", None) == ip_address:
                    existing_static_ip = ip
                    break

    # Normalize and compare existing and desired application data
    desired_static_ip = normalize_static_ip(static_ip)
    current_static_ip = (
        normalize_static_ip(existing_static_ip) if existing_static_ip else {}
    )

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in desired_static_ip.items():
        if key not in fields_to_exclude:
            if key in ["latitude", "longitude"]:  # Special handling for coordinates
                if not diff_suppress_func_coordinate(current_static_ip.get(key), value):
                    differences_detected = True
                    module.warn(
                        f"Difference detected in {key}. Current: {current_static_ip.get(key)}, Desired: {value}"
                    )
            elif current_static_ip.get(key) != value:
                differences_detected = True
                module.warn(
                    f"Difference detected in {key}. Current: {current_static_ip.get(key)}, Desired: {value}"
                )

    if existing_static_ip is not None:
        id = existing_static_ip.get("id")
        existing_static_ip.update(desired_static_ip)
        existing_static_ip["id"] = id

    if state == "present":
        if existing_static_ip is not None:
            if latitude is not None and longitude is not None:
                existing_lat = existing_static_ip.get("latitude")
                existing_long = existing_static_ip.get("longitude")
                new_lat = static_ip.get("latitude")
                new_long = static_ip.get("longitude")

                # Compare and update latitude and longitude if necessary
                if new_lat is not None and not diff_suppress_func_coordinate(
                    existing_lat, new_lat
                ):
                    existing_static_ip["latitude"] = new_lat
                if new_long is not None and not diff_suppress_func_coordinate(
                    existing_long, new_long
                ):
                    existing_static_ip["longitude"] = new_long
            if differences_detected:
                existing_static_ip.update(desired_static_ip)
                existing_static_ip["id"] = id
                """Update"""
                existing_static_ip = deleteNone(
                    dict(
                        static_ip_id=existing_static_ip.get("id", ""),
                        comment=existing_static_ip.get("comment", ""),
                        geo_override=existing_static_ip.get("geo_override", ""),
                        routable_ip=existing_static_ip.get("routable_ip", ""),
                        latitude=existing_static_ip.get("latitude", ""),
                        longitude=existing_static_ip.get("longitude", ""),
                    )
                )
                existing_static_ip = client.traffic.update_static_ip(
                    **existing_static_ip
                ).to_dict()
                module.exit_json(changed=True, data=existing_static_ip)
            else:
                """No Changes Needed"""
                module.exit_json(
                    changed=False, data=existing_static_ip, msg="No changes detected."
                )
        else:
            """Create"""
            static_ip = deleteNone(
                dict(
                    ip_address=static_ip.get("ip_address", ""),
                    comment=static_ip.get("comment", ""),
                    geo_override=static_ip.get("geo_override", ""),
                    routable_ip=static_ip.get("routable_ip", ""),
                    latitude=static_ip.get("latitude", ""),
                    longitude=static_ip.get("longitude", ""),
                )
            )
            static_ip = client.traffic.add_static_ip(**static_ip).to_dict()
            module.exit_json(changed=True, data=static_ip)
    elif (
        state == "absent"
        and existing_static_ip is not None
        and existing_static_ip.get("id") is not None
    ):
        code = client.traffic.delete_static_ip(
            static_ip_id=existing_static_ip.get("id")
        )
        if code > 299:
            module.exit_json(changed=False, data=None)
        module.exit_json(changed=True, data=existing_static_ip)

    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        ip_address=dict(type="str", required=True),
        comment=dict(type="str", required=False),
        geo_override=dict(type="bool", required=False),
        latitude=dict(type="float", required=False),
        longitude=dict(type="float", required=False),
        routable_ip=dict(type="bool", required=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
