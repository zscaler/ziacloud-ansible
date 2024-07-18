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
module: zia_dlp_notification_template_info
short_description: "Get a list of DLP notification templates."
description:
  - "Get a list of DLP notification templates."
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
    description: "The unique identifier for the DLP engine."
    type: int
    required: false
  name:
    type: str
    required: false
    description:
      - The DLP engine name as configured by the admin..
"""

EXAMPLES = r"""
- name: Gets all list of DLP Notification Template
  zscaler.ziacloud.zia_dlp_notification_template_info:
    provider: '{{ provider }}'

- name: Gets a list of DLP Notification Template by name
  zscaler.ziacloud.zia_dlp_notification_template_info:
    provider: '{{ provider }}'
    name: "Standard_Template"
"""

RETURN = r"""
# Returns information about specific DLP Notification Template.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    template_id = module.params.get("id", None)
    template_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    templates = []
    if template_id is not None:
        template = client.dlp.get_dlp_templates(template_id).to_dict()
        templates = [template]
    else:
        templates = client.dlp.list_dlp_templates().to_list()
        if template_name is not None:
            template = None
            for dlp in templates:
                if dlp.get("name", None) == template_name:
                    template = dlp
                    break

            if template is None:
                module.fail_json(
                    msg="Failed to retrieve dlp notification template: '%s'"
                    % (template_name)
                )
            templates = [template]
    module.exit_json(changed=False, templates=templates)


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
