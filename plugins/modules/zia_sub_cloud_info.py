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
module: zia_sub_cloud_info
short_description: "Gets information about ZIA subclouds"
description:
  - "Gets subcloud configurations and excluded data centers."
  - "Retrieves a specific subcloud by ID or name."
  - "If neither id nor name is provided, lists all subclouds."
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
      - Unique identifier for the subcloud.
    required: false
    type: int
  name:
    description:
      - Subcloud name. Used to search for a subcloud by name.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all subclouds
  zscaler.ziacloud.zia_sub_cloud_info:
    provider: '{{ provider }}'

- name: Get a subcloud by ID
  zscaler.ziacloud.zia_sub_cloud_info:
    provider: '{{ provider }}'
    id: 31649

- name: Get a subcloud by name
  zscaler.ziacloud.zia_sub_cloud_info:
    provider: '{{ provider }}'
    name: "US Subcloud"
"""

RETURN = r"""
subclouds:
  description: A list of subclouds fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Unique identifier for the subcloud.
      returned: always
      type: int
    name:
      description: Subcloud name.
      returned: always
      type: str
    dcs:
      description: List of data centers associated with the subcloud.
      returned: when available
      type: list
      elements: dict
      contains:
        id:
          description: Unique identifier for the data center.
          type: int
        name:
          description: Data center name.
          type: str
        country:
          description: Country where the data center is located.
          type: str
    exclusions:
      description: List of data centers excluded from the subcloud.
      returned: when available
      type: list
      elements: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    subcloud_id = module.params.get("id")
    subcloud_name = module.params.get("name")

    client = ZIAClientHelper(module)
    result, _unused, error = client.sub_clouds.list_sub_clouds(
        query_params={"pageSize": 500}
    )
    if error:
        module.fail_json(
            msg=f"Error retrieving subclouds: {to_native(error)}"
        )
    subclouds_list = [s.as_dict() for s in result] if result else []

    if subcloud_id is not None:
        matched = next(
            (s for s in subclouds_list if s.get("id") == subcloud_id),
            None,
        )
        if matched is None:
            module.fail_json(
                msg=f"Subcloud with ID {subcloud_id} not found."
            )
        subclouds_out = [matched]
    elif subcloud_name:
        matched = next(
            (s for s in subclouds_list if s.get("name") == subcloud_name),
            None,
        )
        if matched is None:
            module.fail_json(
                msg=f"Subcloud with name '{subcloud_name}' not found."
            )
        subclouds_out = [matched]
    else:
        subclouds_out = subclouds_list

    module.exit_json(changed=False, subclouds=subclouds_out)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
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
