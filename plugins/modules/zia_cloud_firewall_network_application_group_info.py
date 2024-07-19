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
module: zia_cloud_firewall_network_application_group_info
short_description: "Gets a list of all network application groups."
description:
  - "Gets a list of all network application groups."
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
    description: "A unique identifier of the network application groups"
    required: false
    type: int
  name:
    description: "The name of the network application groups"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all application groups
  zscaler.ziacloud.zia_cloud_firewall_network_application_group_info:
    provider: '{{ provider }}'

- name: Gather Information of an Application Group by Name
  zscaler.ziacloud.zia_cloud_firewall_network_application_group_info:
    provider: '{{ provider }}'
    name: "Microsoft Office365"
"""

RETURN = r"""
app_groups:
  description: List of application groups based on the search criteria provided.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the application group.
      returned: always
      type: int
      sample: 2577531
    name:
      description: The name of the application group.
      returned: always
      type: str
      sample: "Microsoft Office365"
    description:
      description: A description of the application group.
      returned: always
      type: str
      sample: "Microsoft Office365"
    network_applications:
      description: List of network applications associated with this group.
      returned: always
      type: list
      sample: [
          "YAMMER",
          "OFFICE365",
          "SKYPE_FOR_BUSINESS",
          "OUTLOOK", "SHAREPOINT",
          "SHAREPOINT_ADMIN",
          "SHAREPOINT_BLOG",
          "SHAREPOINT_CALENDAR",
          "SHAREPOINT_DOCUMENT",
          "SHAREPOINT_ONLINE",
          "ONEDRIVE"
        ]
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    app_group_id = module.params.get("id", None)
    app_group_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    app_groups = []
    if app_group_id is not None:
        app_group = client.firewall.get_network_app_group(app_group_id).to_dict()
        app_groups = [app_group]
    else:
        app_groups = client.firewall.list_network_app_groups().to_list()
        if app_group_name is not None:
            app_group = None
            for app in app_groups:
                if app.get("name", None) == app_group_name:
                    app_group = app
                    break
            if app_group is None:
                module.fail_json(
                    msg="Failed to retrieve network application groups: '%s'"
                    % (app_group_name)
                )
            app_groups = [app_group]
    module.exit_json(changed=False, app_groups=app_groups)


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
