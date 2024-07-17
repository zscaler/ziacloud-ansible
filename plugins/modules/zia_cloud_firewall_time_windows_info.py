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
module: zia_cloud_firewall_time_windows_info
short_description: "List of time intervals"
description: "Gets a list of time intervals used for by the Firewall policy or the URL Filtering policy."
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
    description: "Unique identifier for Time Interval"
    type: int
  name:
    description: "Name of the Time Interval"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all ZIA Time Intervals
  zscaler.ziacloud.zia_cloud_firewall_time_windows_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a ZIA Time Interval by Name
  zscaler.ziacloud.zia_cloud_firewall_time_windows_info:
    provider: '{{ provider }}'
    name: "Off hours"
"""

RETURN = r"""
# Returns information on all time windows.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    time_window_id = module.params.get("id")
    time_window_name = module.params.get("name")
    client = ZIAClientHelper(module)

    time_windows = client.firewall.list_time_windows()
    if time_windows is None:
        module.fail_json(msg="Failed to retrieve time windows list")

    if time_window_id is not None:
        time_window = next(
            (tw for tw in time_windows if str(tw.get("id")) == str(time_window_id)),
            None,
        )
    elif time_window_name is not None:
        time_window = next(
            (tw for tw in time_windows if tw.get("name") == time_window_name), None
        )
    else:
        module.exit_json(changed=False, time_windows=time_windows)
        return

    if time_window:
        module.exit_json(changed=False, time_windows=time_window)
    else:
        msg = f"Time window {'with ID ' + str(time_window_id) if time_window_id is not None else 'named ' + time_window_name} not found"
        module.fail_json(msg=msg)


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
