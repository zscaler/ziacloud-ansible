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
module: zia_browser_control_policy
short_description: "Manages the Browser Control policy settings"
description:
  - "Updates the Browser Control policy settings for the organization."
  - "Browser Control is a singleton resource; there is one policy per organization."
  - "Create and update both use the update API. Delete is a no-op (policy cannot be removed)."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
    - This is a singleton resource. state=absent performs a no-op (policy cannot be deleted).
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  plugin_check_frequency:
    description:
      - Specifies how frequently the service checks browsers and relevant applications to warn users
        regarding outdated or vulnerable browsers, plugins, and applications.
      - If not set, the warnings are disabled.
    required: false
    type: str
    choices:
      - DAILY
      - WEEKLY
      - MONTHLY
      - EVERY_2_HOURS
      - EVERY_4_HOURS
      - EVERY_6_HOURS
      - EVERY_8_HOURS
      - EVERY_12_HOURS
  bypass_plugins:
    description:
      - List of plugins that need to be bypassed for warnings.
      - Has effect only if enable_warnings is true. If not set, all vulnerable plugins are warned.
    required: false
    type: list
    elements: str
  bypass_applications:
    description:
      - List of applications that need to be bypassed for warnings.
      - Has effect only if enable_warnings is true. If not set, all vulnerable applications are warned.
    required: false
    type: list
    elements: str
  blocked_internet_explorer_versions:
    description: Versions of Microsoft browser that need to be blocked. If not set, all allowed.
    required: false
    type: list
    elements: str
  blocked_chrome_versions:
    description: Versions of Google Chrome browser that need to be blocked. If not set, all allowed.
    required: false
    type: list
    elements: str
  blocked_firefox_versions:
    description: Versions of Mozilla Firefox browser that need to be blocked. If not set, all allowed.
    required: false
    type: list
    elements: str
  blocked_safari_versions:
    description: Versions of Apple Safari browser that need to be blocked. If not set, all allowed.
    required: false
    type: list
    elements: str
  blocked_opera_versions:
    description: Versions of Opera browser that need to be blocked. If not set, all allowed.
    required: false
    type: list
    elements: str
  bypass_all_browsers:
    description: If true, all browsers are bypassed for warnings.
    required: false
    type: bool
  allow_all_browsers:
    description: If true, allows all browsers and their versions access to the internet.
    required: false
    type: bool
  enable_warnings:
    description: If true, warnings are enabled.
    required: false
    type: bool
  enable_smart_browser_isolation:
    description: If true, Smart Browser Isolation is enabled.
    required: false
    type: bool
  smart_isolation_profile_id:
    description: The isolation profile ID (integer).
    required: false
    type: int
  smart_isolation_profile:
    description:
      - The browser isolation profile. Provide as a dict with C(id) key (UUID string).
      - Example C({"id": "161d0907-0a57-4aab-98c2-eccbd651c448"}).
    required: false
    type: dict
  smart_isolation_groups:
    description: List of group IDs for which the Smart Isolation rule is applied.
    required: false
    type: list
    elements: int
  smart_isolation_users:
    description: List of user IDs for which the Smart Isolation rule is applied.
    required: false
    type: list
    elements: int
"""

EXAMPLES = r"""
- name: Update Browser Control policy with basic settings
  zscaler.ziacloud.zia_browser_control_policy:
    provider: '{{ provider }}'
    plugin_check_frequency: DAILY
    bypass_plugins:
      - ACROBAT
      - FLASH
    bypass_applications:
      - OUTLOOKEXP
    enable_warnings: true
    allow_all_browsers: false

- name: Update Browser Control policy with Smart Browser Isolation
  zscaler.ziacloud.zia_browser_control_policy:
    provider: '{{ provider }}'
    plugin_check_frequency: DAILY
    enable_warnings: true
    enable_smart_browser_isolation: true
    smart_isolation_profile:
      id: "161d0907-0a57-4aab-98c2-eccbd651c448"
    smart_isolation_users:
      - 5452145
    smart_isolation_groups:
      - 21568541
"""

RETURN = r"""
data:
  description: The Browser Control policy settings after the operation.
  returned: on success
  type: dict
  contains:
    plugin_check_frequency:
      description: How frequently browsers/plugins are checked.
      type: str
    bypass_plugins:
      description: List of plugins bypassed for warnings.
      type: list
      elements: str
    bypass_applications:
      description: List of applications bypassed for warnings.
      type: list
      elements: str
    blocked_internet_explorer_versions:
      description: Blocked Microsoft browser versions.
      type: list
      elements: str
    blocked_chrome_versions:
      description: Blocked Chrome versions.
      type: list
      elements: str
    blocked_firefox_versions:
      description: Blocked Firefox versions.
      type: list
      elements: str
    blocked_safari_versions:
      description: Blocked Safari versions.
      type: list
      elements: str
    blocked_opera_versions:
      description: Blocked Opera versions.
      type: list
      elements: str
    bypass_all_browsers:
      description: Whether all browsers are bypassed.
      type: bool
    allow_all_browsers:
      description: Whether all browsers are allowed.
      type: bool
    enable_warnings:
      description: Whether warnings are enabled.
      type: bool
    enable_smart_browser_isolation:
      description: Whether Smart Browser Isolation is enabled.
      type: bool
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)

BROWSER_CONTROL_ATTRIBUTES = [
    "plugin_check_frequency",
    "bypass_plugins",
    "bypass_applications",
    "blocked_internet_explorer_versions",
    "blocked_chrome_versions",
    "blocked_firefox_versions",
    "blocked_safari_versions",
    "blocked_opera_versions",
    "bypass_all_browsers",
    "allow_all_browsers",
    "enable_warnings",
    "enable_smart_browser_isolation",
    "smart_isolation_profile_id",
    "smart_isolation_profile",
    "smart_isolation_groups",
    "smart_isolation_users",
]

PLUGIN_CHECK_FREQUENCY_CHOICES = [
    "DAILY",
    "WEEKLY",
    "MONTHLY",
    "EVERY_2_HOURS",
    "EVERY_4_HOURS",
    "EVERY_6_HOURS",
    "EVERY_8_HOURS",
    "EVERY_12_HOURS",
]


def _normalize_list(val):
    """Normalize list for order-independent comparison."""
    if val is None:
        return None
    if isinstance(val, list):
        return sorted([str(x) for x in val]) if val else []
    return val


def _extract_ids_from_refs(val):
    """Extract id values from list of refs (dicts with id key) or return list of ints as-is."""
    if val is None:
        return None
    if not isinstance(val, list):
        return val
    ids = []
    for item in val:
        if isinstance(item, dict) and "id" in item:
            ids.append(item["id"])
        elif isinstance(item, (int, float)):
            ids.append(int(item))
        else:
            ids.append(item)
    return sorted([str(x) for x in ids])


def normalize_policy(policy):
    """Normalize policy dict for comparison."""
    if not policy:
        return {}
    norm = {}
    for key, val in policy.items():
        if key in ("smart_isolation_users", "smart_isolation_groups"):
            norm[key] = _extract_ids_from_refs(val)
        elif key in (
            "bypass_plugins",
            "bypass_applications",
            "blocked_internet_explorer_versions",
            "blocked_chrome_versions",
            "blocked_firefox_versions",
            "blocked_safari_versions",
            "blocked_opera_versions",
        ):
            norm[key] = _normalize_list(val)
        elif key == "smart_isolation_profile":
            if isinstance(val, dict) and "id" in val:
                norm[key] = {"id": val["id"]}
            elif val is not None:
                norm[key] = val
            else:
                norm[key] = None
        else:
            norm[key] = val
    return norm


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    policy_params = {
        p: module.params.get(p)
        for p in BROWSER_CONTROL_ATTRIBUTES
        if module.params.get(p) is not None
    }

    # Build smart_isolation_profile for SDK if provided
    if "smart_isolation_profile" in policy_params:
        prof = policy_params["smart_isolation_profile"]
        if isinstance(prof, dict) and prof.get("id"):
            policy_params["smart_isolation_profile"] = {"id": prof["id"]}
        elif isinstance(prof, list) and len(prof) > 0 and isinstance(prof[0], dict):
            policy_params["smart_isolation_profile"] = {"id": prof[0].get("id")}
        else:
            policy_params.pop("smart_isolation_profile", None)

    # Always fetch current state (singleton)
    result, _unused, error = client.browser_control_settings.get_browser_control_settings()
    if error:
        module.fail_json(
            msg=f"Error retrieving Browser Control policy: {to_native(error)}"
        )

    existing_policy = result.as_dict() if result and hasattr(result, "as_dict") else {}

    if state == "absent":
        # Singleton cannot be deleted - no-op
        module.exit_json(
            changed=False,
            msg="Browser Control policy is a singleton and cannot be deleted.",
            data=existing_policy,
        )

    normalized_desired = normalize_policy(policy_params)
    normalized_existing = normalize_policy(existing_policy)

    differences_detected = False
    for key, value in normalized_desired.items():
        existing_val = normalized_existing.get(key)
        if key in ("smart_isolation_users", "smart_isolation_groups"):
            if _extract_ids_from_refs(value) != _extract_ids_from_refs(existing_val):
                differences_detected = True
                module.warn(
                    f"Difference detected in {key}. Current: {existing_val}, Desired: {value}"
                )
        elif existing_val != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {existing_val}, Desired: {value}"
            )

    if module.check_mode:
        module.exit_json(changed=differences_detected)

    if differences_detected:
        # Merge existing with user params - don't clear fields user didn't specify
        update_params = dict(existing_policy) if existing_policy else {}
        for k, v in policy_params.items():
            if v is not None:
                update_params[k] = v

        # Ensure smart_isolation users/groups are list of IDs (API expects ints)
        for key in ("smart_isolation_users", "smart_isolation_groups"):
            if key in update_params and update_params[key]:
                ids = _extract_ids_from_refs(update_params[key])
                update_params[key] = [int(x) for x in ids] if ids else []

        updated, _unused, error = client.browser_control_settings.update_browser_control_settings(
            **update_params
        )
        if error:
            module.fail_json(
                msg=f"Error updating Browser Control policy: {to_native(error)}"
            )
        data = updated.as_dict() if updated and hasattr(updated, "as_dict") else updated
        module.exit_json(changed=True, data=data)
    else:
        module.exit_json(changed=False, data=existing_policy)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            plugin_check_frequency=dict(
                type="str",
                required=False,
                choices=PLUGIN_CHECK_FREQUENCY_CHOICES,
            ),
            bypass_plugins=dict(type="list", elements="str", required=False),
            bypass_applications=dict(type="list", elements="str", required=False),
            blocked_internet_explorer_versions=dict(
                type="list", elements="str", required=False
            ),
            blocked_chrome_versions=dict(type="list", elements="str", required=False),
            blocked_firefox_versions=dict(type="list", elements="str", required=False),
            blocked_safari_versions=dict(type="list", elements="str", required=False),
            blocked_opera_versions=dict(type="list", elements="str", required=False),
            bypass_all_browsers=dict(type="bool", required=False),
            allow_all_browsers=dict(type="bool", required=False),
            enable_warnings=dict(type="bool", required=False),
            enable_smart_browser_isolation=dict(type="bool", required=False),
            smart_isolation_profile_id=dict(type="int", required=False),
            smart_isolation_profile=dict(type="dict", required=False),
            smart_isolation_groups=dict(type="list", elements="int", required=False),
            smart_isolation_users=dict(type="list", elements="int", required=False),
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
