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
module: zia_atp_malicious_urls_info
short_description: "Retrieves the malicious URLs added to the denylist"
description:
  - "Retrieves the malicious URLs added to the denylist in the (ATP) policy"
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  id:
    description: "The unique identifier for the rule label."
    type: int
    required: false
  name:
    description: "The rule label name."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets all list of rule label
  zscaler.ziacloud.zia_rule_labels_info:
    provider: '{{ provider }}'

- name: Gets a list of rule label by name
  zscaler.ziacloud.zia_rule_labels_info:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
labels:
  description: A list of rule labels fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the rule label.
      returned: always
      type: int
      sample: 3687131
    name:
      description: The name of the rule label.
      returned: always
      type: str
      sample: "Example"
    description:
      description: A description of the rule label.
      returned: always
      type: str
      sample: "Example description"
    created_by:
      description: Information about the user who created the rule label.
      returned: always
      type: complex
      contains:
        id:
          description: The identifier of the user who created the rule label.
          returned: always
          type: int
          sample: 44772836
        name:
          description: The name of the user who created the rule label.
          returned: always
          type: str
          sample: "admin@44772833.zscalertwo.net"
    last_modified_by:
      description: Information about the user who last modified the rule label.
      returned: always
      type: complex
      contains:
        id:
          description: The identifier of the user who last modified the rule label.
          returned: always
          type: int
          sample: 44772836
        name:
          description: The name of the user who last modified the rule label.
          returned: always
          type: str
          sample: "admin@44772833.zscalertwo.net"
    last_modified_time:
      description: The Unix timestamp when the rule label was last modified.
      returned: always
      type: int
      sample: 1721347034
    referenced_rule_count:
      description: The number of rules that reference this label.
      returned: always
      type: int
      sample: 0
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper

def normalize_urls(malicious_urls):
    """Utility to normalize and sort URLs for comparison."""
    return sorted(set([url.strip().lower() for url in malicious_urls if url]))

def core(module):
    client = ZIAClientHelper(module)

    malicious_urls = module.params.get("malicious_urls")
    state = module.params.get("state")

    current_list, _, error = client.atp_policy.get_atp_malicious_urls()
    if error:
        module.fail_json(msg=f"Error fetching malicious URLs: {to_native(error)}")

    current_normalized = normalize_urls(current_list)
    desired_normalized = normalize_urls(malicious_urls)

    urls_to_add = list(set(desired_normalized) - set(current_normalized))
    urls_to_remove = list(set(current_normalized) & set(desired_normalized)) if state == "absent" else []

    module.warn(f"✅ Current list: {current_normalized}")
    module.warn(f"🎯 Desired list: {desired_normalized}")
    module.warn(f"➕ URLs to add: {urls_to_add}")
    module.warn(f"➖ URLs to remove: {urls_to_remove}")

    if module.check_mode:
        module.exit_json(changed=bool(urls_to_add or urls_to_remove))

    updated_urls = current_normalized
    changed = False

    if state == "present" and urls_to_add:
        updated_urls, _, error = client.atp_policy.add_atp_malicious_urls(urls_to_add)
        if error:
            module.fail_json(msg=f"Error adding malicious URLs: {to_native(error)}")
        changed = True

    elif state == "absent" and urls_to_remove:
        updated_urls, _, error = client.atp_policy.delete_atp_malicious_urls(urls_to_remove)
        if error:
            module.fail_json(msg=f"Error removing malicious URLs: {to_native(error)}")
        changed = True

    module.exit_json(changed=changed, malicious_urls=updated_urls)

def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        malicious_urls=dict(type="list", elements="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())

if __name__ == "__main__":
    main()
