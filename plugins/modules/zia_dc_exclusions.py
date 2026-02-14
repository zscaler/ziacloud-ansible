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
module: zia_dc_exclusions
short_description: "Manages ZIA DC (datacenter) exclusions"
description:
  - "Creates, updates, or deletes datacenter exclusions for traffic forwarding."
  - "DC exclusions disable tunnels to specific Zscaler datacenters for a time period."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
    - Use C(datacenter_id) or C(name) to reference an existing exclusion for update/delete.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  datacenter_id:
    description:
      - Datacenter ID (dcid) to exclude. Required for create. Used with C(name) for update/delete lookup.
    required: false
    type: int
  name:
    description:
      - Datacenter name for lookup when updating or deleting (used if datacenter_id is not set).
    required: false
    type: str
  start_time:
    description:
      - Unix timestamp when the exclusion window starts.
      - Either start_time or start_time_utc must be set.
    required: false
    type: int
  start_time_utc:
    description:
      - Exclusion window start (UTC). Format C(MM/DD/YYYY HH:MM:SS am/pm).
      - If set, overrides start_time.
    required: false
    type: str
  end_time:
    description:
      - Unix timestamp when the exclusion window ends.
      - Either end_time or end_time_utc must be set.
    required: false
    type: int
  end_time_utc:
    description:
      - Exclusion window end (UTC). Format C(MM/DD/YYYY HH:MM:SS am/pm).
      - If set, overrides end_time.
    required: false
    type: str
  description:
    description:
      - Description of the DC exclusion. Maximum 10240 characters.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Create a DC exclusion
  zscaler.ziacloud.zia_dc_exclusions:
    provider: '{{ provider }}'
    datacenter_id: 5313
    start_time_utc: "04/29/2025 02:51:00 pm"
    end_time_utc: "05/01/2025 02:00:00 pm"
    description: "Maintenance window"

- name: Update a DC exclusion by datacenter ID
  zscaler.ziacloud.zia_dc_exclusions:
    provider: '{{ provider }}'
    datacenter_id: 5313
    description: "Updated description"
    start_time: 1745941860
    end_time: 1746114660

- name: Delete a DC exclusion
  zscaler.ziacloud.zia_dc_exclusions:
    provider: '{{ provider }}'
    datacenter_id: 5313
    state: absent
"""

RETURN = r"""
data:
  description: The DC exclusion resource record.
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


def _parse_utc_to_epoch(utc_str):
    """Parse UTC string to Unix timestamp."""
    if not utc_str or not isinstance(utc_str, str):
        return None
    try:
        dt = datetime.strptime(utc_str.strip(), EXCLUSION_UTC_FMT)
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


def _resolve_start_time(params):
    """Resolve start_time from start_time or start_time_utc."""
    utc = params.get("start_time_utc")
    if utc:
        return _parse_utc_to_epoch(utc)
    return params.get("start_time")


def _resolve_end_time(params):
    """Resolve end_time from end_time or end_time_utc."""
    utc = params.get("end_time_utc")
    if utc:
        return _parse_utc_to_epoch(utc)
    return params.get("end_time")


def _exclusion_to_dict(ex):
    """Convert exclusion to dict for comparison."""
    d = ex.as_dict() if hasattr(ex, "as_dict") else (ex if isinstance(ex, dict) else {})
    return {
        "dcid": d.get("dcid") or d.get("dc_id"),
        "start_time": d.get("start_time") or d.get("startTime"),
        "end_time": d.get("end_time") or d.get("endTime"),
        "description": d.get("description") or "",
    }


def core(module):
    state = module.params.get("state")
    datacenter_id = module.params.get("datacenter_id")
    name = module.params.get("name")

    client = ZIAClientHelper(module)

    result, _unused, error = client.traffic_datacenters.list_dc_exclusions()
    if error:
        module.fail_json(msg=f"Error listing DC exclusions: {to_native(error)}")
    all_exclusions = list(result or [])

    existing = None
    if datacenter_id is not None:
        for ex in all_exclusions:
            eid = getattr(ex, "dcid", None) or (ex.get("dcid") if isinstance(ex, dict) else None)
            if eid == datacenter_id:
                existing = ex
                break
    elif name:
        name_lower = name.lower()
        for ex in all_exclusions:
            dn = getattr(ex, "dc_name", None)
            dn_name = ""
            if dn:
                if hasattr(dn, "name"):
                    dn_name = dn.name or ""
                elif hasattr(dn, "as_dict") and dn:
                    dn_name = (dn.as_dict() or {}).get("name", "")
            elif isinstance(ex, dict):
                dn = ex.get("dc_name") or ex.get("dcName") or {}
                dn_name = dn.get("name", "") if isinstance(dn, dict) else ""
            if name_lower in dn_name.lower():
                existing = ex
                break

    start_epoch = _resolve_start_time(module.params)
    end_epoch = _resolve_end_time(module.params)
    description = module.params.get("description") or ""

    if state == "present":
        if not existing and not datacenter_id:
            module.fail_json(msg="datacenter_id is required for create.")
        if start_epoch is None and end_epoch is None and not existing:
            module.fail_json(msg="Either start_time/start_time_utc and end_time/end_time_utc must be set for create.")

    dcid = datacenter_id
    if dcid is None and existing:
        dcid = getattr(existing, "dcid", None) or (existing.get("dcid") if isinstance(existing, dict) else None)

    if module.check_mode:
        if state == "present":
            if existing:
                existing_dict = _exclusion_to_dict(existing)
                use_start = start_epoch if start_epoch is not None else existing_dict.get("start_time")
                use_end = end_epoch if end_epoch is not None else existing_dict.get("end_time")
                use_desc = description if module.params.get("description") is not None else (existing_dict.get("description") or "")
                cur_start = existing_dict.get("start_time")
                cur_end = existing_dict.get("end_time")
                cur_desc = existing_dict.get("description") or ""
                if use_start != cur_start or use_end != cur_end or use_desc != cur_desc:
                    module.exit_json(changed=True)
            else:
                module.exit_json(changed=True)
        elif state == "absent" and existing:
            module.exit_json(changed=True)
        module.exit_json(changed=False)

    if state == "present":
        if existing:
            existing_dict = _exclusion_to_dict(existing)
            use_start = start_epoch if start_epoch is not None else existing_dict.get("start_time")
            use_end = end_epoch if end_epoch is not None else existing_dict.get("end_time")
            use_desc = description if module.params.get("description") is not None else (existing_dict.get("description") or "")
            if use_start is None or use_end is None:
                module.fail_json(msg="start_time and end_time are required for update.")
            # Idempotency: only update if something changed
            cur_start = existing_dict.get("start_time")
            cur_end = existing_dict.get("end_time")
            cur_desc = existing_dict.get("description") or ""
            if (use_start == cur_start and use_end == cur_end and use_desc == cur_desc):
                existing_out = existing.as_dict() if hasattr(existing, "as_dict") else existing
                module.exit_json(changed=False, data=existing_out)
            updated, _unused, error = client.traffic_datacenters.update_dc_exclusion(
                dcid,
                start_time=use_start,
                end_time=use_end,
                description=use_desc,
            )
            if error:
                module.fail_json(msg=f"Error updating DC exclusion: {to_native(error)}")
            out = updated.as_dict() if hasattr(updated, "as_dict") else updated
            module.exit_json(changed=True, data=out)
        else:
            if start_epoch is None or end_epoch is None:
                module.fail_json(msg="start_time/start_time_utc and end_time/end_time_utc are required for create.")
            added, _unused, error = client.traffic_datacenters.add_dc_exclusion(
                dcid=dcid,
                start_time=start_epoch,
                end_time=end_epoch,
                description=description,
            )
            if error:
                module.fail_json(msg=f"Error creating DC exclusion: {to_native(error)}")
            result_list = added if isinstance(added, list) else [added]
            out = result_list[0].as_dict() if result_list and hasattr(result_list[0], "as_dict") else (result_list[0] if result_list else {})
            module.exit_json(changed=True, data=out)

    elif state == "absent":
        if existing:
            _unused, _unused, error = client.traffic_datacenters.delete_dc_exclusion(dcid)
            if error:
                module.fail_json(msg=f"Error deleting DC exclusion: {to_native(error)}")
            existing_dict = existing.as_dict() if hasattr(existing, "as_dict") else existing
            module.exit_json(changed=True, data=existing_dict)
        else:
            module.exit_json(changed=False, data={})

    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            datacenter_id=dict(type="int", required=False),
            name=dict(type="str", required=False),
            start_time=dict(type="int", required=False),
            start_time_utc=dict(type="str", required=False),
            end_time=dict(type="int", required=False),
            end_time_utc=dict(type="str", required=False),
            description=dict(type="str", required=False),
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
