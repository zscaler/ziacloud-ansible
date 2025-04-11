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
module: zia_sandbox_advanced_settings
short_description: Manage ZIA Advanced Cloud Sandbox MD5 hash blocklist.
description:
  - This module manages a custom list of MD5 file hashes that are blocked by ZIA Advanced Cloud Sandbox.
  - It allows adding or removing hashes from the blocklist and ensures idempotency.
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
  - Zscaler SDK Python (obtainable from PyPI U(https://pypi.org/project/zscaler-sdk-python/))
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  file_hashes_to_be_blocked:
    description:
      - A list of unique MD5 file hashes to be blocked by Sandbox.
      - Maximum of 10000 MD5 file hashes can be blocked.
    type: list
    elements: str
    required: true

"""

EXAMPLES = r"""
- name: Add MD5 Hashes to Sandbox Blocklist
  zscaler.ziacloud.zia_sandbox_advanced_settings:
    provider: '{{ provider }}'
    file_hashes_to_be_blocked:
      - "42914d6d213a20a2684064be5c80ffa9"
      - "c0202cf6aeab8437c638533d14563d35"
      - "1ca31319721740ecb79f4b9ee74cd9b0"
  register: result

- name: Read MD5 Hashes from file
set_fact:
    md5_hashes: "{{ lookup('file', 'md5_hashes.txt').splitlines() }}"

- name: Add MD5 Hashes to Custom List
zscaler.ziacloud.zia_sandbox_advanced_settings:
    provider: '{{ provider }}'
    state: absent
    file_hashes_to_be_blocked: "{{ md5_hashes }}"
register: result
"""

EXAMPLES = r"""
- name: Retrieves the custom list of MD5 file hashes that are blocked by Sandbox.
  zscaler.ziacloud.zia_sandbox_advanced_settings:
"""

RETURN = r"""
# Default return values
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper

import re


def hash_type_and_validate(hash_string):
    md5_pattern = r"^[a-f0-9]{32}$"
    sha1_pattern = r"^[a-f0-9]{40}$"
    sha256_pattern = r"^[a-f0-9]{64}$"

    if re.fullmatch(md5_pattern, hash_string, re.IGNORECASE):
        return True, "MD5"
    if re.fullmatch(sha1_pattern, hash_string, re.IGNORECASE):
        return False, "SHA1"
    if re.fullmatch(sha256_pattern, hash_string, re.IGNORECASE):
        return False, "SHA256"
    return False, "Invalid Format"


def core(module):
    state = module.params.get("state")
    file_hashes_to_be_blocked = module.params.get("file_hashes_to_be_blocked", [])

    # Validate MD5 hashes
    for hash_string in file_hashes_to_be_blocked:
        is_valid, hash_type = hash_type_and_validate(hash_string)
        if not is_valid:
            module.fail_json(
                msg=f"Invalid hash '{hash_string}' ({hash_type}). Only MD5 hashes are supported."
            )

    client = ZIAClientHelper(module)
    sandbox_api = client.sandbox

    current_data, _, error = sandbox_api.get_behavioral_analysis()
    if error or not current_data:
        module.fail_json(msg=f"Error retrieving behavioral analysis config: {to_native(error)}")

    current_hashes = current_data.get("fileHashesToBeBlocked", [])
    desired_set = set(file_hashes_to_be_blocked)
    current_set = set(current_hashes)

    change_needed = (
        desired_set != current_set if state == "present" else bool(current_set)
    )

    if module.check_mode:
        module.exit_json(
            changed=change_needed,
            msg="MD5 hash list will be updated." if change_needed else "No change needed."
        )

    if change_needed:
        if state == "present":
            _, _, error = sandbox_api.add_hash_to_custom_list(list(desired_set))
            action_msg = "MD5 hash list has been updated."
        elif state == "absent":
            _, _, error = sandbox_api.add_hash_to_custom_list([])  # clear list
            action_msg = "MD5 hash list has been cleared."

        if error:
            module.fail_json(msg=f"Error updating MD5 hash list: {to_native(error)}")

        # ✅ Fetch updated count
        count_data, _, error = sandbox_api.get_file_hash_count()
        if error or not count_data:
            module.fail_json(msg=f"Error retrieving hash count: {to_native(error)}")

        module.exit_json(
            changed=True,
            msg=action_msg,
            file_hash_count=count_data,
        )

    else:
        # ✅ Fetch current count again
        count_data, _, error = sandbox_api.get_file_hash_count()
        if error or not count_data:
            module.fail_json(msg=f"Error retrieving hash count: {to_native(error)}")

        module.exit_json(
            changed=False,
            msg="No change needed for MD5 hash list.",
            file_hash_count=count_data,
        )


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        file_hashes_to_be_blocked=dict(type="list", elements="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
