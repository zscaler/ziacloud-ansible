#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, Zscaler Technology Alliances <zscaler-partner-labs@z-bd.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_dlp_notification_template
short_description: Manage Zscaler Internet Access (ZIA) DLP Notification Templates
description:
  - This module allows for the management of Zscaler Internet Access (ZIA) Data Loss Prevention (DLP) Notification Templates.
  - It supports the creation, updating, and deletion of DLP Notification Templates.
  - It allows for the customization of the subject line, message body (both plain text and HTML), and various other settings related to DLP notifications.
version_added: "1.0.0"
author: William Guilherme (@willguibr)
requirements:
  - Zscaler SDK Python (obtainable from PyPI U(https://pypi.org/project/zscaler-sdk-python/))
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.credentials_set
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.enabled_state
options:
  id:
    description:
      - The unique identifier for the DLP notification template. Required if updating or deleting a template.
    type: int
  name:
    description:
      - The name of the DLP notification template.
    type: str
    required: True
  subject:
    description:
      - The subject line that is displayed within the DLP notification email.
    type: str
  attach_content:
    description:
      - If set to true, the content that triggered the violation is attached to the DLP notification email.
    type: bool
  plain_text_message:
    description:
      - The template for the plain text UTF-8 message body that is displayed in the DLP notification email.
    type: str
  html_message:
    description:
      - The template for the HTML message body that is displayed in the DLP notification email.
    type: str
  tls_enabled:
    description:
      - If set to true, enables TLS for the DLP notification template.
    type: bool
"""

EXAMPLES = """
- name: Create a new DLP Notification Template
  zia_dlp_notification_template:
    name: "Standard_DLP_Template"
    subject: "DLP Violation Alert"
    attach_content: true
    tls_enabled: true
    plain_text_message: |
      "The attached content triggered a Web DLP rule for your organization..."
    html_message: |
      "<html><body>The attached content triggered a Web DLP rule...</body></html>"

- name: Update an existing DLP Notification Template
  zia_dlp_notification_template:
    name: "Updated_DLP_Template"
    subject: "Updated DLP Violation Alert"
    state: "present"

- name: Delete a DLP Notification Template
  zia_dlp_notification_template:
    name: Updated_DLP_Template
    state: "absent"
"""

RETURN = """
  - A dictionary containing the details of the DLP Notification Template.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_dlp_template(template):
    """
    Normalize dlp notification template data by setting computed values.
    """
    normalized = template.copy()

    computed_values = [
        "id",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)
    params = [
        "id",
        "name",
        "subject",
        "attach_content",
        "plain_text_message",
        "html_message",
        "tls_enabled",
    ]
    template = {param: module.params.get(param) for param in params}

    template_id = template.get("id")
    existing_template = (
        client.dlp.get_dlp_templates(template_id).to_dict() if template_id else None
    )
    if not existing_template and template.get("name"):
        templates = client.dlp.list_dlp_templates().to_list()
        existing_template = next(
            (t for t in templates if t.get("name") == template.get("name")), None
        )

    if existing_template:
        updated_template = {k: v for k, v in template.items() if v is not None}
        differences_detected = any(
            existing_template.get(k) != v for k, v in updated_template.items()
        )

        if state == "present" and differences_detected:
            updated_template["template_id"] = existing_template["id"]
            response = client.dlp.update_dlp_template(**updated_template).to_dict()
            module.exit_json(changed=True, data=response)
        elif state == "absent":
            client.dlp.delete_dlp_template(template_id=existing_template["id"])
            module.exit_json(changed=True, data=existing_template)
        else:
            module.exit_json(changed=False, data=existing_template)
    else:
        if state == "present":
            response = client.dlp.add_dlp_template(**template).to_dict()
            module.exit_json(changed=True, data=response)
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        subject=dict(type="str", required=True),
        tls_enabled=dict(type="bool", required=False),
        attach_content=dict(type="bool", required=False),
        plain_text_message=dict(type="str", required=True),
        html_message=dict(type="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
