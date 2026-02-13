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
module: zia_alerts_info
short_description: "Gets information about ZIA alert subscriptions"
description:
  - "Gets a list of alert subscriptions or retrieves a specific subscription by ID or email."
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
      - The unique identifier for the alert subscription.
      - System-generated identifier for the alert subscription.
    required: false
    type: int
  email:
    description:
      - The email address of the alert recipient.
      - Used to look up a subscription by recipient email.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all alert subscriptions
  zscaler.ziacloud.zia_alerts_info:
    provider: '{{ provider }}'

- name: Get an alert subscription by ID
  zscaler.ziacloud.zia_alerts_info:
    provider: '{{ provider }}'
    id: 123456

- name: Get an alert subscription by email
  zscaler.ziacloud.zia_alerts_info:
    provider: '{{ provider }}'
    email: "alerts@example.com"
"""

RETURN = r"""
subscriptions:
  description: A list of alert subscriptions fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the alert subscription (system-generated).
      returned: always
      type: int
      sample: 123456
    email:
      description: The email address of the alert recipient.
      returned: always
      type: str
      sample: "alerts@example.com"
    description:
      description: Additional comments or information about the alert subscription.
      returned: always
      type: str
    deleted:
      description: Indicates whether the alert subscription is marked as deleted.
      returned: when available
      type: bool
    pt0_severities:
      description: Severity levels for Patient 0 Alert class (CRITICAL, MAJOR, MINOR, INFO, DEBUG).
      returned: always
      type: list
      elements: str
    secure_severities:
      description: Severity levels for Secure Alert class.
      returned: always
      type: list
      elements: str
    manage_severities:
      description: Severity levels for Manage Alert class.
      returned: always
      type: list
      elements: str
    comply_severities:
      description: Severity levels for Comply Alert class.
      returned: always
      type: list
      elements: str
    system_severities:
      description: Severity levels for System Alerts class.
      returned: always
      type: list
      elements: str
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    subscription_id = module.params.get("id")
    subscription_email = module.params.get("email")

    client = ZIAClientHelper(module)
    subscriptions = []

    if subscription_id is not None:
        sub_obj, _unused, error = client.alert_subscriptions.get_alert_subscription(
            subscription_id
        )
        if error or sub_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve alert subscription with ID '{subscription_id}': {to_native(error)}"
            )
        subscriptions = [sub_obj.as_dict()]
    else:
        result, _unused, error = (
            client.alert_subscriptions.list_alert_subscriptions()
        )
        if error:
            module.fail_json(
                msg=f"Error retrieving alert subscriptions: {to_native(error)}"
            )

        sub_list = [s.as_dict() for s in result] if result else []

        if subscription_email:
            matched = next(
                (s for s in sub_list if s.get("email") == subscription_email),
                None,
            )
            if not matched:
                available = [s.get("email") for s in sub_list]
                module.fail_json(
                    msg=f"Alert subscription with email '{subscription_email}' not found. Available emails: {available}"
                )
            subscriptions = [matched]
        else:
            subscriptions = sub_list

    module.exit_json(changed=False, subscriptions=subscriptions)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        email=dict(type="str", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["id", "email"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
