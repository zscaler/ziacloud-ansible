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
module: zia_email_profiles
short_description: "Adds a ZIA Email Profile."
description:
  - "Adds, updates, or deletes a ZIA Email Profile used as a recipient profile for notifications."
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
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
    description: "The unique identifier for the email profile."
    type: int
    required: false
  name:
    description: "The name of the email profile."
    required: true
    type: str
  description:
    description:
      - Additional information about the email profile.
    required: false
    type: str
  emails:
    description:
      - The list of email addresses associated with the email profile.
    required: false
    type: list
    elements: str
"""

EXAMPLES = r"""
- name: Create/Update/Delete an email profile.
  zscaler.ziacloud.zia_email_profiles:
    provider: '{{ provider }}'
    name: "Example"
    description: "Example email profile"
    emails:
      - john.doe@example.com
      - mary.jane@example.com
"""

RETURN = r"""
# The newly created email profile resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_profile(profile):
    """
    Remove computed attributes from a profile dict to make comparison easier.
    """
    normalized = profile.copy() if profile else {}
    computed_values = [
        "last_modified_time",
        "last_modified_by",
        "created_by",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    # Normalize emails to a sorted list for order-insensitive comparison
    if normalized.get("emails") is not None:
        normalized["emails"] = sorted(normalized["emails"])
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    profile_params = {p: module.params.get(p) for p in ["id", "name", "description", "emails"]}
    profile_id = profile_params.get("id")
    profile_name = profile_params.get("name")

    existing_profile = None

    if profile_id:
        result, _unused, error = client.email_profiles.get_email_profile(profile_id)
        if error:
            module.fail_json(msg=f"Error fetching email profile with id {profile_id}: {to_native(error)}")
        existing_profile = result.as_dict() if result else None
    else:
        result, _unused, error = client.email_profiles.list_email_profiles()
        if error:
            module.fail_json(msg=f"Error listing email profiles: {to_native(error)}")
        profiles_list = [p.as_dict() for p in result] if result else []
        if profile_name:
            for profile in profiles_list:
                if profile.get("name") == profile_name:
                    existing_profile = profile
                    break

    # Drop None values from desired so unset optionals don't trigger false diffs
    desired = {k: v for k, v in profile_params.items() if v is not None}
    normalized_desired = normalize_profile(desired)
    normalized_existing = normalize_profile(existing_profile) if existing_profile else {}

    differences_detected = False
    for key, value in normalized_desired.items():
        if key == "id":
            continue
        if normalized_existing.get(key) != value:
            differences_detected = True
            module.warn(f"Difference detected in {key}. Current: {normalized_existing.get(key)}, Desired: {value}")

    if module.check_mode:
        if state == "present" and (existing_profile is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_profile:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_profile:
            if differences_detected:
                profile_id_to_update = existing_profile.get("id")
                if not profile_id_to_update:
                    module.fail_json(msg="Cannot update email profile: ID is missing from the existing resource.")

                updated_profile, _unused, error = client.email_profiles.update_email_profile(
                    profile_id_to_update,
                    name=profile_params.get("name"),
                    description=profile_params.get("description"),
                    emails=profile_params.get("emails"),
                )
                if error:
                    module.fail_json(msg=f"Error updating email profile: {to_native(error)}")
                module.exit_json(changed=True, data=updated_profile.as_dict())
            else:
                module.exit_json(changed=False, data=existing_profile)
        else:
            new_profile, _unused, error = client.email_profiles.add_email_profile(
                name=profile_params.get("name"),
                description=profile_params.get("description"),
                emails=profile_params.get("emails"),
            )
            if error:
                module.fail_json(msg=f"Error adding email profile: {to_native(error)}")
            module.exit_json(changed=True, data=new_profile.as_dict())

    elif state == "absent":
        if existing_profile:
            profile_id_to_delete = existing_profile.get("id")
            if not profile_id_to_delete:
                module.fail_json(msg="Cannot delete email profile: ID is missing from the existing resource.")

            _unused, _unused, error = client.email_profiles.delete_email_profile(profile_id_to_delete)
            if error:
                module.fail_json(msg=f"Error deleting email profile: {to_native(error)}")
            module.exit_json(changed=True, data=existing_profile)
        else:
            module.exit_json(changed=False, data={})

    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            id=dict(type="int", required=False),
            name=dict(type="str", required=True),
            description=dict(type="str", required=False),
            emails=dict(type="list", elements="str", required=False),
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
