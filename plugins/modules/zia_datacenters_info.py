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
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zia_datacenters_info
short_description: "Gets information about ZIA datacenters"
description:
  - "Retrieves the list of Zscaler data centers (DCs) that can be excluded from service."
  - "Filter by datacenter ID, name, or city."
  - "If no filter is provided, lists all datacenters."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
    - Datacenters are read-only; there is no resource module for creating/updating them.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  datacenter_id:
    description:
      - Filter datacenters by ID.
    required: false
    type: int
  name:
    description:
      - Filter datacenters by name (case-insensitive partial match).
    required: false
    type: str
  city:
    description:
      - Filter datacenters by city (case-insensitive partial match).
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all datacenters
  zscaler.ziacloud.zia_datacenters_info:
    provider: '{{ provider }}'

- name: Get datacenter by ID
  zscaler.ziacloud.zia_datacenters_info:
    provider: '{{ provider }}'
    datacenter_id: 5313

- name: Get datacenters by name
  zscaler.ziacloud.zia_datacenters_info:
    provider: '{{ provider }}'
    name: "San Jose"

- name: Get datacenters by city
  zscaler.ziacloud.zia_datacenters_info:
    provider: '{{ provider }}'
    city: "Chicago"
"""

RETURN = r"""
datacenters:
  description: List of datacenter entries.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Unique identifier for the datacenter.
      type: int
    name:
      description: Zscaler data center name.
      type: str
    provider:
      description: Provider of the datacenter.
      type: str
    city:
      description: City where the datacenter is located.
      type: str
    timezone:
      description: Timezone of the datacenter.
      type: str
    lat:
      description: Latitude coordinate (legacy field).
      type: int
    longi:
      description: Longitude coordinate (legacy field).
      type: int
    latitude:
      description: Latitude coordinate.
      type: float
    longitude:
      description: Longitude coordinate.
      type: float
    gov_only:
      description: Whether this is a government-only datacenter.
      type: bool
    third_party_cloud:
      description: Whether this is a third-party cloud datacenter.
      type: bool
    upload_bandwidth:
      description: Upload bandwidth in bytes per second.
      type: int
    download_bandwidth:
      description: Download bandwidth in bytes per second.
      type: int
    owned_by_customer:
      description: Whether the datacenter is owned by the customer.
      type: bool
    managed_bcp:
      description: Whether the datacenter is managed by BCP.
      type: bool
    dont_publish:
      description: Whether the datacenter should not be published.
      type: bool
    dont_provision:
      description: Whether the datacenter should not be provisioned.
      type: bool
    not_ready_for_use:
      description: Whether the datacenter is not ready for use.
      type: bool
    for_future_use:
      description: Whether the datacenter is reserved for future use.
      type: bool
    regional_surcharge:
      description: Whether there is a regional surcharge for this datacenter.
      type: bool
    create_time:
      description: Timestamp when the datacenter was created.
      type: int
    last_modified_time:
      description: Timestamp when the datacenter was last modified.
      type: int
    virtual:
      description: Whether this is a virtual datacenter.
      type: bool
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def _get(d, *keys):
    """Get first present key from dict (supports both snake_case and camelCase)."""
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


def _flatten_datacenter(dc):
    """Convert datacenter object/dict to return format."""
    d = dc.as_dict() if hasattr(dc, "as_dict") else (dc if isinstance(dc, dict) else {})
    return {
        "id": _get(d, "id"),
        "name": _get(d, "name"),
        "provider": _get(d, "provider"),
        "city": _get(d, "city"),
        "timezone": _get(d, "timezone"),
        "lat": _get(d, "lat"),
        "longi": _get(d, "longi"),
        "latitude": _get(d, "latitude"),
        "longitude": _get(d, "longitude"),
        "gov_only": _get(d, "gov_only", "govOnly"),
        "third_party_cloud": _get(d, "third_party_cloud", "thirdPartyCloud"),
        "upload_bandwidth": _get(d, "upload_bandwidth", "uploadBandwidth"),
        "download_bandwidth": _get(d, "download_bandwidth", "downloadBandwidth"),
        "owned_by_customer": _get(d, "owned_by_customer", "ownedByCustomer"),
        "managed_bcp": _get(d, "managed_bcp", "managedBcp"),
        "dont_publish": _get(d, "dont_publish", "dontPublish"),
        "dont_provision": _get(d, "dont_provision", "dontProvision"),
        "not_ready_for_use": _get(d, "not_ready_for_use", "notReadyForUse"),
        "for_future_use": _get(d, "for_future_use", "forFutureUse"),
        "regional_surcharge": _get(d, "regional_surcharge", "regionalSurcharge"),
        "create_time": _get(d, "create_time", "createTime"),
        "last_modified_time": _get(d, "last_modified_time", "lastModifiedTime"),
        "virtual": _get(d, "virtual"),
    }


def core(module):
    datacenter_id = module.params.get("datacenter_id")
    filter_name = module.params.get("name")
    filter_city = module.params.get("city")

    client = ZIAClientHelper(module)

    result, _unused, error = client.traffic_datacenters.list_datacenters()
    if error:
        module.fail_json(msg=f"Error retrieving datacenters: {to_native(error)}")
    all_dcs = list(result or [])

    filtered = all_dcs
    if datacenter_id is not None:
        filtered = [dc for dc in filtered if (getattr(dc, "id", None) or (dc.get("id") if isinstance(dc, dict) else None)) == datacenter_id]
    if filter_name:
        name_lower = filter_name.lower()
        filtered = [dc for dc in filtered if name_lower in (getattr(dc, "name", None) or (dc.get("name") if isinstance(dc, dict) else "") or "").lower()]
    if filter_city:
        city_lower = filter_city.lower()
        filtered = [dc for dc in filtered if city_lower in (getattr(dc, "city", None) or (dc.get("city") if isinstance(dc, dict) else "") or "").lower()]

    datacenters_out = [_flatten_datacenter(dc) for dc in filtered]
    module.exit_json(changed=False, datacenters=datacenters_out)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        datacenter_id=dict(type="int", required=False),
        name=dict(type="str", required=False),
        city=dict(type="str", required=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
