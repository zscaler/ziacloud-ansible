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
module: zia_sub_cloud
short_description: "Manages ZIA subcloud configurations"
description:
  - "Updates subcloud excluded data centers based on the specified cloud ID."
  - "Subclouds cannot be created or deleted via the API; only exclusions can be updated."
  - "Use the info resource C(zia_sub_cloud_info) to look up cloud IDs."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
    - C(cloud_id) is required to identify the subcloud.
    - C(state=absent) is a no-op; subclouds cannot be deleted via the API.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  cloud_id:
    description:
      - Unique identifier for the subcloud.
      - Used as the path parameter for the update API.
    required: true
    type: int
  exclusions:
    description:
      - Set of data centers excluded from the subcloud.
    required: false
    type: list
    elements: dict
    suboptions:
      datacenter:
        description: The excluded datacenter reference.
        type: list
        elements: dict
        required: true
        suboptions:
          id:
            description: Unique identifier for the datacenter.
            type: int
            required: true
          name:
            description: Datacenter name.
            type: str
          country:
            description: Country where the datacenter is located.
            type: str
      country:
        description: Country where the excluded data center is located.
        type: str
        required: true
      end_time:
        description: Exclusion end time (Unix timestamp).
        type: int
      end_time_utc:
        description:
          - Exclusion end time in UTC. Format C(MM/DD/YYYY HH:MM:SS am/pm).
          - If set, overrides end_time.
        type: str
"""

EXAMPLES = r"""
- name: Update subcloud exclusions
  zscaler.ziacloud.zia_sub_cloud:
    provider: '{{ provider }}'
    cloud_id: 31649
    exclusions:
      - datacenter:
          - id: 5313
            name: "DC Name"
        country: "United States"
        end_time: 1735689600

- name: Update subcloud with end_time_utc
  zscaler.ziacloud.zia_sub_cloud:
    provider: '{{ provider }}'
    cloud_id: 31649
    exclusions:
      - datacenter:
          - id: 5313
        country: "United States"
        end_time_utc: "01/15/2025 12:00:00 pm"
"""

RETURN = r"""
data:
  description: The subcloud resource record.
  returned: on success
  type: dict
"""

from datetime import datetime, timezone
from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)

EXCLUSION_UTC_FMT = "%m/%d/%Y %I:%M:%S %p"


def _parse_end_time_utc(utc_str):
    """Parse end_time_utc string to Unix timestamp (UTC)."""
    if not utc_str or not isinstance(utc_str, str):
        return None
    try:
        dt = datetime.strptime(utc_str.strip(), EXCLUSION_UTC_FMT)
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


def _resolve_end_time(item):
    """Resolve end_time from end_time or end_time_utc."""
    end_time = item.get("end_time")
    end_time_utc = item.get("end_time_utc")
    if end_time_utc:
        return _parse_end_time_utc(end_time_utc)
    return end_time


def _build_exclusions(exclusions):
    """Build exclusions list for API from module params."""
    if not exclusions:
        return []
    out = []
    for item in exclusions:
        dc_list = item.get("datacenter") or []
        dc = dc_list[0] if isinstance(dc_list, list) and dc_list else {}
        if not dc or dc.get("id") is None:
            continue
        exclusion = {
            "country": item.get("country") or "",
            "datacenter": {
                "id": int(dc["id"]),
                "name": dc.get("name") or "",
            },
        }
        if dc.get("country"):
            exclusion["datacenter"]["extensions"] = {"country": dc["country"]}
        end_time = _resolve_end_time(item)
        if end_time is not None:
            exclusion["end_time"] = int(end_time)
        out.append(exclusion)
    return out


def _normalize_exclusion_from_user(exc):
    """Normalize user exclusion param for comparison."""
    if not exc:
        return {}
    dc_list = exc.get("datacenter") or []
    dc = dc_list[0] if isinstance(dc_list, list) and dc_list else {}
    if not isinstance(dc, dict):
        dc = {}
    end_time = _resolve_end_time(exc)
    return {
        "country": exc.get("country") or "",
        "datacenter_id": dc.get("id"),
        "end_time": end_time,
    }


def _normalize_exclusions_list(norm_list):
    """Sort normalized exclusions for comparison."""
    if not norm_list:
        return []
    return sorted(
        norm_list,
        key=lambda x: (x.get("datacenter_id") or 0, x.get("country") or ""),
    )


def core(module):
    state = module.params.get("state")
    cloud_id = module.params.get("cloud_id")
    exclusions = module.params.get("exclusions")

    client = ZIAClientHelper(module)

    if state == "absent":
        # Subclouds cannot be deleted via API
        module.exit_json(
            changed=False,
            data={},
            msg="Subcloud deletion is not supported by the ZIA API.",
        )

    # Fetch existing subcloud
    result, _unused, error = client.sub_clouds.list_sub_clouds(query_params={"pageSize": 500})
    if error:
        module.fail_json(msg=f"Error listing subclouds: {to_native(error)}")
    subclouds_raw = list(result or [])
    existing_raw = next(
        (s for s in subclouds_raw if getattr(s, "id", None) == cloud_id),
        None,
    )

    if existing_raw is None:
        module.fail_json(msg=f"Subcloud with cloud_id {cloud_id} not found. Use zia_sub_cloud_info to list available subclouds.")

    existing = existing_raw.as_dict()

    desired_exclusions = _build_exclusions(exclusions)
    # Use raw exclusion objects to get datacenter (dropped by Exclusions.request_format in as_dict)
    existing_exclusions_raw = getattr(existing_raw, "exclusions", None) or []
    existing_list = []
    for e in existing_exclusions_raw:
        dc_id = None
        dc = getattr(e, "datacenter", None)
        if dc is not None:
            dc_id = getattr(dc, "id", None)
        country = getattr(e, "country", None) or ""
        end_time = getattr(e, "end_time", None)
        existing_list.append(
            {
                "country": country,
                "datacenter_id": dc_id,
                "end_time": end_time,
            }
        )
    desired_list = [_normalize_exclusion_from_user(exc) for exc in (exclusions or []) if (exc.get("datacenter") or [{}])[0].get("id") is not None]
    differences_detected = _normalize_exclusions_list(existing_list) != _normalize_exclusions_list(desired_list)

    if module.check_mode:
        module.exit_json(changed=differences_detected)

    if differences_detected:
        update_params = {"exclusions": desired_exclusions}
        updated, _unused, error = client.sub_clouds.update_sub_clouds(
            cloud_id,
            **update_params,
        )
        if error:
            module.fail_json(msg=f"Error updating subcloud: {to_native(error)}")
        module.exit_json(changed=True, data=updated.as_dict())
    else:
        module.exit_json(changed=False, data=existing)


def main():
    datacenter_subspec = {
        "id": dict(type="int", required=True),
        "name": dict(type="str", required=False),
        "country": dict(type="str", required=False),
    }
    exclusion_subspec = {
        "datacenter": dict(
            type="list",
            elements="dict",
            options=datacenter_subspec,
            required=True,
        ),
        "country": dict(type="str", required=True),
        "end_time": dict(type="int", required=False),
        "end_time_utc": dict(type="str", required=False),
    }
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            cloud_id=dict(type="int", required=True),
            exclusions=dict(
                type="list",
                elements="dict",
                options=exclusion_subspec,
                required=False,
            ),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
