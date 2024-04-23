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
module: zia_location_management_facts
short_description: "Gets locations only, not sub-locations."
description:
  - "Gets locations only, not sub-locations."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
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
  zscaler.ziacloud.zia_location_management_facts:
    provider: '{{ provider }}'

- name: Gather Information Details of ZIA Location By Name
  zscaler.ziacloud.zia_location_management_facts:
    provider: '{{ provider }}'
    name: "USA-SJC37"
"""

RETURN = r"""
# Returns information on a specified ZIA Location.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    client = ZIAClientHelper(module)
    location_name = module.params.get("name", None)
    location_id = module.params.get("id", None)
    locations = []
    if location_id is not None:
        locationBox = client.locations.get_location(location_id=location_id)
        if locationBox is None:
            module.fail_json(
                msg="Failed to retrieve location management ID: '%s'" % (location_id)
            )
        locations = [locationBox.to_dict()]
    elif location_name is not None:
        locationBox = client.locations.get_location(location_name=location_name)
        if locationBox is None:
            module.fail_json(
                msg="Failed to retrieve location management Name: '%s'"
                % (location_name)
            )
        locations = [locationBox.to_dict()]
    else:
        locations = client.locations.list_locations().to_list()
    module.exit_json(changed=False, data=locations)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
