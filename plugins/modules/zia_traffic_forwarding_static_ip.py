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
module: zia_traffic_forwarding_static_ip
short_description: "Adds a static IP address."
description:
  - "Adds a static IP address."
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
    description: "The unique identifier for the static IP address"
    type: int
    required: false
  ip_address:
    description:
      - The static IP address
    required: false
    type: str
  routable_ip:
    description:
      - Indicates whether a non-RFC 1918 IP address is publicly routable.
      - This attribute is ignored if there is no ZIA Private Service Edge associated to the organization."
    required: false
    type: bool
  comment:
    description:
      - Additional information about this static IP address
    required: false
    type: str
  geo_override:
    description:
      - If not set, geographic coordinates and city are automatically determined from the IP address.
      - Otherwise, the latitude and longitude coordinates must be provided.
    required: false
    type: bool
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
  city:
    description:
      - Specifies the city object associated with the static IP address.
      - Required if geo_override is enabled and city-level granularity is needed.
    type: dict
    required: false
    suboptions:
      id:
        description:
          - The unique identifier for the city object.
        type: int
        required: true
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


def normalize_static_ip(static_ip):
    """Normalize static ip data by removing computed values"""
    normalized = static_ip.copy() if static_ip else {}
    computed_values = ["id"]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    params = [
        "id",
        "ip_address",
        "geo_override",
        "latitude",
        "longitude",
        "routable_ip",
        "comment",
        "city",
    ]

    static_ip = {param: module.params.get(param) for param in params}
    static_ip_id = static_ip.get("id")
    ip_address = static_ip.get("ip_address")

    # Fix city parameter if it's a list (from playbook input)
    if isinstance(static_ip.get("city"), list):
        if len(static_ip["city"]) > 0 and isinstance(static_ip["city"][0], dict):
            static_ip["city"] = static_ip["city"][0]
        else:
            static_ip["city"] = None

    # Validate geo override requirements
    if static_ip.get("geo_override") and (static_ip.get("latitude") is None or static_ip.get("longitude") is None):
        module.fail_json(msg="When 'geo_override' is set to True, 'latitude' and 'longitude' must be provided.")

    # Validate coordinates if provided
    latitude = static_ip.get("latitude")
    longitude = static_ip.get("longitude")
    if latitude is not None and longitude is not None:
        unused_result_lat, lat_errors = validate_latitude(latitude)
        unused_result_lon, lon_errors = validate_longitude(longitude)
        if lat_errors:
            module.fail_json(msg="; ".join(lat_errors))
        if lon_errors:
            module.fail_json(msg="; ".join(lon_errors))

    existing_static_ip = None
    if static_ip_id:
        result = client.traffic_static_ip.get_static_ip(static_ip_id)
        if result[2]:  # Error check
            module.fail_json(msg=f"Error fetching static IP ID {static_ip_id}: {to_native(result[2])}")
        existing_static_ip = result[0].as_dict() if result[0] else None
    else:
        result = client.traffic_static_ip.list_static_ips()
        if result[2]:  # Error check
            module.fail_json(msg=f"Error listing static IPs: {to_native(result[2])}")
        for ip in result[0]:
            if ip.ip_address == ip_address:
                existing_static_ip = ip.as_dict()
                break

    # Normalize and compare states
    desired = normalize_static_ip(static_ip)
    current = normalize_static_ip(existing_static_ip) if existing_static_ip else {}

    # Drift detection
    differences_detected = False
    for key, value in desired.items():
        if key in ["latitude", "longitude"]:  # Special handling for coordinates
            if not diff_suppress_func_coordinate(current.get(key), value):
                differences_detected = True
                module.warn(f"Difference detected in {key}. Current: {current.get(key)}, Desired: {value}")
        elif current.get(key) != value:
            differences_detected = True
            module.warn(f"Difference detected in {key}. Current: {current.get(key)}, Desired: {value}")

    if module.check_mode:
        if state == "present" and (existing_static_ip is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_static_ip:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_static_ip:
            if differences_detected:
                update_data = deleteNone(
                    {
                        "static_ip_id": existing_static_ip["id"],
                        "ip_address": desired.get("ip_address"),
                        "comment": desired.get("comment"),
                        "geo_override": desired.get("geo_override"),
                        "routable_ip": desired.get("routable_ip"),
                        "latitude": desired.get("latitude"),
                        "longitude": desired.get("longitude"),
                        "city": desired.get("city"),
                    }
                )
                module.warn("Payload Update for SDK: {}".format(update_data))
                module.warn("Static IP address attributes cannot be modified at this time. Update skipped.")
                # Skip the actual API call but return the desired state
                module.exit_json(
                    changed=False,
                    data=existing_static_ip,
                    msg="Static IP updates are currently not supported by the API. Update skipped.",
                )
            else:
                module.exit_json(changed=False, data=existing_static_ip)
        else:
            create_data = deleteNone(
                {
                    "ip_address": desired.get("ip_address"),
                    "comment": desired.get("comment"),
                    "geo_override": desired.get("geo_override"),
                    "routable_ip": desired.get("routable_ip"),
                    "latitude": desired.get("latitude"),
                    "longitude": desired.get("longitude"),
                    "city": desired.get("city"),
                }
            )
            module.warn("Payload Update for SDK: {}".format(create_data))
            created = client.traffic_static_ip.add_static_ip(**create_data)
            if created[2]:
                module.fail_json(msg=f"Error creating static IP: {to_native(created[2])}")
            module.exit_json(changed=True, data=created[0].as_dict())
    elif state == "absent":
        if existing_static_ip:
            static_ip_to_delete = existing_static_ip.get("id")
            if not static_ip_to_delete:
                module.fail_json(msg="Cannot delete static IP: ID is missing from the existing resource.")

            _unused, _unused, error = client.traffic_static_ip.delete_static_ip(static_ip_to_delete)
            if error:
                module.fail_json(msg=f"Error deleting static IP: {to_native(error)}")
            module.exit_json(changed=True, data=existing_static_ip)
        else:
            module.exit_json(changed=False, data={})

    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        ip_address=dict(type="str", required=False),
        comment=dict(type="str", required=False),
        city=dict(
            type="dict",
            options=dict(id=dict(type="int", required=True)),
            required=False,
        ),
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
