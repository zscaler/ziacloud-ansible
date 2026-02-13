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
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zia_alerts
short_description: "Manages ZIA alert subscriptions"
description:
  - "Adds, updates, or removes ZIA alert subscriptions."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description:
      - The unique identifier for the alert subscription.
      - System-generated identifier. Used to reference an existing subscription for update or delete.
    required: false
    type: int
  email:
    description:
      - The email address of the alert recipient.
    required: true
    type: str
  description:
    description:
      - Additional comments or information about the alert subscription.
    required: false
    type: str
  pt0_severities:
    description:
      - Lists the severity levels of the Patient 0 Alert class information that the recipient receives.
    required: false
    type: list
    elements: str
    choices:
      - CRITICAL
      - MAJOR
      - MINOR
      - INFO
      - DEBUG
  secure_severities:
    description:
      - Lists the severity levels of the Secure Alert class information that the recipient receives.
    required: false
    type: list
    elements: str
    choices:
      - CRITICAL
      - MAJOR
      - MINOR
      - INFO
      - DEBUG
  manage_severities:
    description:
      - Lists the severity levels of the Manage Alert class information that the recipient receives.
    required: false
    type: list
    elements: str
    choices:
      - CRITICAL
      - MAJOR
      - MINOR
      - INFO
      - DEBUG
  comply_severities:
    description:
      - Lists the severity levels of the Comply Alert class information that the recipient receives.
    required: false
    type: list
    elements: str
    choices:
      - CRITICAL
      - MAJOR
      - MINOR
      - INFO
      - DEBUG
  system_severities:
    description:
      - Lists the severity levels of the System Alerts class information that the recipient receives.
    required: false
    type: list
    elements: str
    choices:
      - CRITICAL
      - MAJOR
      - MINOR
      - INFO
      - DEBUG
"""

EXAMPLES = r"""
- name: Create an alert subscription
  zscaler.ziacloud.zia_alerts:
    provider: '{{ provider }}'
    email: "alerts@example.com"
    description: "Production alert subscription"
    pt0_severities:
      - CRITICAL
      - MAJOR
    secure_severities:
      - CRITICAL
      - MAJOR
      - MINOR
    manage_severities:
      - CRITICAL
    comply_severities:
      - CRITICAL
    system_severities:
      - CRITICAL
      - MAJOR

- name: Update an alert subscription by ID
  zscaler.ziacloud.zia_alerts:
    provider: '{{ provider }}'
    id: 123456
    email: "alerts@example.com"
    description: "Updated description"

- name: Delete an alert subscription
  zscaler.ziacloud.zia_alerts:
    provider: '{{ provider }}'
    id: 123456
    state: absent
"""

RETURN = r"""
data:
  description: The alert subscription resource record.
  returned: on success
  type: dict
  contains:
    id:
      description: The unique identifier for the alert subscription.
      type: int
    email:
      description: The email address of the alert recipient.
      type: str
    description:
      description: Additional comments or information about the alert subscription.
      type: str
    pt0_severities:
      description: Severity levels for Patient 0 Alert class.
      type: list
      elements: str
    secure_severities:
      description: Severity levels for Secure Alert class.
      type: list
      elements: str
    manage_severities:
      description: Severity levels for Manage Alert class.
      type: list
      elements: str
    comply_severities:
      description: Severity levels for Comply Alert class.
      type: list
      elements: str
    system_severities:
      description: Severity levels for System Alerts class.
      type: list
      elements: str
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)

ALERT_SUBSCRIPTION_ATTRIBUTES = [
    "email",
    "description",
    "pt0_severities",
    "secure_severities",
    "manage_severities",
    "comply_severities",
    "system_severities",
]

SEVERITY_CHOICES = ["CRITICAL", "MAJOR", "MINOR", "INFO", "DEBUG"]


def _normalize_list_for_compare(val):
    """Normalize a list for comparison (sort to ignore order)."""
    if val is None:
        return None
    if isinstance(val, list):
        return sorted([str(x) for x in val]) if val else []
    return val


def normalize_alert_subscription(sub):
    """
    Remove computed attributes and normalize for comparison.
    """
    if not sub:
        return {}
    normalized = sub.copy()
    normalized.pop("id", None)
    # Normalize list attributes for order-independent comparison
    for key in [
        "pt0_severities",
        "secure_severities",
        "manage_severities",
        "comply_severities",
        "system_severities",
    ]:
        if key in normalized:
            normalized[key] = _normalize_list_for_compare(normalized[key])
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    subscription_id = module.params.get("id")
    subscription_email = module.params.get("email")

    alert_params = {
        p: module.params.get(p)
        for p in ALERT_SUBSCRIPTION_ATTRIBUTES
        if module.params.get(p) is not None
    }

    existing_subscription = None

    if subscription_id:
        result, _unused, error = client.alert_subscriptions.get_alert_subscription(
            subscription_id
        )
        if error:
            module.fail_json(
                msg=f"Error fetching alert subscription with id {subscription_id}: {to_native(error)}"
            )
        existing_subscription = result.as_dict()
    else:
        result, _unused, error = client.alert_subscriptions.list_alert_subscriptions()
        if error:
            module.fail_json(
                msg=f"Error listing alert subscriptions: {to_native(error)}"
            )
        subscriptions_list = [s.as_dict() for s in result] if result else []
        if subscription_email:
            for sub in subscriptions_list:
                if sub.get("email") == subscription_email:
                    existing_subscription = sub
                    break

    normalized_desired = normalize_alert_subscription(alert_params)
    normalized_existing = (
        normalize_alert_subscription(existing_subscription)
        if existing_subscription
        else {}
    )

    differences_detected = False
    for key, value in normalized_desired.items():
        norm_val = _normalize_list_for_compare(value)
        if normalized_existing.get(key) != norm_val:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing.get(key)}, Desired: {norm_val}"
            )

    if module.check_mode:
        if state == "present" and (
            existing_subscription is None or differences_detected
        ):
            module.exit_json(changed=True)
        elif state == "absent" and existing_subscription:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_subscription:
            if differences_detected:
                sub_id_to_update = existing_subscription.get("id")
                if not sub_id_to_update:
                    module.fail_json(
                        msg="Cannot update alert subscription: ID is missing from the existing resource."
                    )

                updated_sub, _unused, error = (
                    client.alert_subscriptions.update_alert_subscription(
                        sub_id_to_update,
                        **alert_params,
                    )
                )
                if error:
                    module.fail_json(
                        msg=f"Error updating alert subscription: {to_native(error)}"
                    )
                module.exit_json(changed=True, data=updated_sub.as_dict())
            else:
                module.exit_json(changed=False, data=existing_subscription)
        else:
            new_sub, _unused, error = client.alert_subscriptions.add_alert_subscription(
                **alert_params
            )
            if error:
                module.fail_json(
                    msg=f"Error adding alert subscription: {to_native(error)}"
                )
            module.exit_json(changed=True, data=new_sub.as_dict())

    elif state == "absent":
        if existing_subscription:
            sub_id_to_delete = existing_subscription.get("id")
            if not sub_id_to_delete:
                module.fail_json(
                    msg="Cannot delete alert subscription: ID is missing from the existing resource."
                )

            _unused, _unused, error = (
                client.alert_subscriptions.delete_alert_subscription(
                    sub_id_to_delete
                )
            )
            if error:
                module.fail_json(
                    msg=f"Error deleting alert subscription: {to_native(error)}"
                )
            module.exit_json(changed=True, data=existing_subscription)
        else:
            module.exit_json(changed=False, data={})

    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            id=dict(type="int", required=False),
            email=dict(type="str", required=True),
            description=dict(type="str", required=False),
            pt0_severities=dict(
                type="list",
                elements="str",
                choices=SEVERITY_CHOICES,
                required=False,
            ),
            secure_severities=dict(
                type="list",
                elements="str",
                choices=SEVERITY_CHOICES,
                required=False,
            ),
            manage_severities=dict(
                type="list",
                elements="str",
                choices=SEVERITY_CHOICES,
                required=False,
            ),
            comply_severities=dict(
                type="list",
                elements="str",
                choices=SEVERITY_CHOICES,
                required=False,
            ),
            system_severities=dict(
                type="list",
                elements="str",
                choices=SEVERITY_CHOICES,
                required=False,
            ),
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
