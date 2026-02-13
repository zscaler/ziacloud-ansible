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
module: zia_dc_exclusions_info
short_description: "Gets information about ZIA DC (datacenter) exclusions"
description:
  - "Gets datacenter exclusions configured for traffic forwarding."
  - "Retrieves exclusions by datacenter ID or name (partial match)."
  - "If neither id nor datacenter_id nor name is provided, lists all exclusions."
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
    description:
      - Filter by resource id (datacenter ID as string).
    required: false
    type: str
  datacenter_id:
    description:
      - Filter by datacenter ID (dcid).
    required: false
    type: int
  name:
    description:
      - Filter by datacenter name (case-insensitive partial match).
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all DC exclusions
  zscaler.ziacloud.zia_dc_exclusions_info:
    provider: '{{ provider }}'

- name: Get DC exclusion by datacenter ID
  zscaler.ziacloud.zia_dc_exclusions_info:
    provider: '{{ provider }}'
    datacenter_id: 5313

- name: Get DC exclusions by datacenter name
  zscaler.ziacloud.zia_dc_exclusions_info:
    provider: '{{ provider }}'
    name: "San Jose"
"""

RETURN = r"""
exclusions:
  description: List of DC exclusion entries.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The exclusion identifier (datacenter ID as string).
      type: str
    dc_id:
      description: Datacenter ID (dcid) for the exclusion.
      type: int
    expired:
      description: Whether the exclusion has expired.
      type: bool
    start_time:
      description: Unix timestamp when the exclusion window starts.
      type: int
    end_time:
      description: Unix timestamp when the exclusion window ends.
      type: int
    description:
      description: Description of the DC exclusion.
      type: str
    dc_name_id:
      description: Datacenter ID from the dcName reference.
      type: int
    dc_name:
      description: Datacenter name from the dcName reference.
      type: str
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def _flatten_exclusion(ex):
    """Convert exclusion object/dict to return format."""
    d = ex.as_dict() if hasattr(ex, "as_dict") else (ex if isinstance(ex, dict) else {})
    dc_name = d.get("dc_name") or d.get("dcName") or {}
    if hasattr(dc_name, "as_dict") and dc_name:
        dc_name = dc_name.as_dict()
    elif not isinstance(dc_name, dict):
        dc_name = {}
    dc_id = d.get("dcid") or d.get("dc_id")
    return {
        "id": str(dc_id) if dc_id is not None else "",
        "dc_id": dc_id,
        "expired": d.get("expired", False),
        "start_time": d.get("start_time") or d.get("startTime"),
        "end_time": d.get("end_time") or d.get("endTime"),
        "description": d.get("description") or "",
        "dc_name_id": dc_name.get("id", 0),
        "dc_name": dc_name.get("name", ""),
    }


def core(module):
    filter_id = module.params.get("id")
    datacenter_id = module.params.get("datacenter_id")
    filter_name = module.params.get("name")

    client = ZIAClientHelper(module)

    result, _unused, error = client.traffic_datacenters.list_dc_exclusions()
    if error:
        module.fail_json(
            msg=f"Error retrieving DC exclusions: {to_native(error)}"
        )
    all_exclusions = list(result or [])

    def _get_dcid(e):
        if isinstance(e, dict):
            return e.get("dcid") or e.get("dc_id")
        return getattr(e, "dcid", None) or getattr(e, "dc_id", None)

    def _get_dc_name(e):
        if isinstance(e, dict):
            dn = e.get("dc_name") or e.get("dcName") or {}
        else:
            dn = getattr(e, "dc_name", None) or getattr(e, "dcName", None)
        if hasattr(dn, "as_dict") and dn:
            return (dn.as_dict() or {}).get("name", "")
        return dn.get("name", "") if isinstance(dn, dict) else ""

    filtered = all_exclusions
    target_id = None
    if filter_id:
        try:
            target_id = int(filter_id)
        except ValueError:
            target_id = None
    if datacenter_id is not None:
        target_id = datacenter_id
    if target_id is not None:
        filtered = [e for e in filtered if _get_dcid(e) == target_id]
    if filter_name:
        name_lower = filter_name.lower()
        filtered = [e for e in filtered if name_lower in _get_dc_name(e).lower()]

    if filter_id and not filtered:
        module.fail_json(
            msg=f"No DC exclusion found with datacenter id {filter_id}."
        )

    exclusions_out = [_flatten_exclusion(ex) for ex in filtered]
    module.exit_json(changed=False, exclusions=exclusions_out)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="str", required=False),
        datacenter_id=dict(type="int", required=False),
        name=dict(type="str", required=False),
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
