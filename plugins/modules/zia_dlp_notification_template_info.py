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
templates:
  description: A list of DLP notification templates.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier of the DLP notification template.
      returned: always
      type: int
      sample: 6523
    name:
      description: The name of the DLP notification template.
      returned: always
      type: str
      sample: "Standard_Template"
    subject:
      description: The subject line for the DLP notification email, potentially containing template variables.
      returned: always
      type: str
      sample: "DLP Violation: ${TRANSACTION_ID} ${RULENAME}"
    attach_content:
      description: Indicates if the content that triggered the DLP rule is attached to the email.
      returned: always
      type: bool
      sample: true
    plain_text_message:
      description: The plain text version of the DLP notification email body, potentially containing template variables.
      returned: always
      type: str
      sample: "Detailed DLP notification message in plain text format with placeholders for transaction ID, user, URL, etc."
    html_message:
      description: The HTML version of the DLP notification email body, potentially containing template variables and HTML formatting.
      returned: always
      type: str
      sample: "Detailed DLP notification message in HTML format with placeholders and stylings for various components like user, URL, etc."
    tls_enabled:
      description: Indicates if TLS is enabled for the sending of the notification email.
      returned: always
      type: bool
      sample: true
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    template_id = module.params.get("id")
    template_name = module.params.get("name")

    client = ZIAClientHelper(module)
    templates = []

    if template_id is not None:
        template_obj, _unused, error = client.dlp_templates.get_dlp_templates(template_id)
        if error or template_obj is None:
            module.fail_json(msg=f"Failed to retrieve DLP Notification Template with ID '{template_id}': {to_native(error)}")
        templates = [template_obj.as_dict()]
    else:
        result, _unused, error = client.dlp_templates.list_dlp_templates()
        if error:
            module.fail_json(msg=f"Error retrieving DLP Notification Templates: {to_native(error)}")

        template_list = [t.as_dict() for t in result] if result else []

        if template_name:
            matched = next((t for t in template_list if t.get("name") == template_name), None)
            if not matched:
                available = [t.get("name") for t in template_list]
                module.fail_json(msg=f"DLP Notification Template named '{template_name}' not found. Available: {available}")
            templates = [matched]
        else:
            templates = template_list

    module.exit_json(changed=False, templates=templates)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["name", "id"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
