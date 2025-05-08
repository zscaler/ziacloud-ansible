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
module: zia_atp_security_exceptions
short_description: "Updates security exceptions for the ATP policy"
description:
  - "Updates security exceptions for the ATP policy"
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
  - zscaler.ziacloud.fragments.state

options:
  bypass_urls:
    description: "Allowlist URLs that are not inspected by the ATP policy"
    type: list
    elements: str
    required: false
"""

EXAMPLES = r"""
- name: Updates security exceptions for the ATP policy
  zscaler.ziacloud.zia_atp_security_exceptions:
    provider: '{{ provider }}'
    bypass_urls:
      - goodurl01.acme.com
      - goodurl02.acme.com
      - goodurl03.acme.com
      - goodurl04.acme.com
      - goodurl05.acme.com
      - goodurl06.acme.com
"""

RETURN = r"""
#  Bypass URL exceptions.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_urls(bypass_urls):
    """Utility to normalize and sort URLs for comparison."""
    return sorted(set([url.strip().lower() for url in bypass_urls if url]))


def core(module):
    client = ZIAClientHelper(module)

    bypass_urls = module.params.get("bypass_urls")
    if bypass_urls is None:
        module.fail_json(
            msg="The 'bypass_urls' parameter must be a list. Use `bypass_urls: []` to explicitly provide an empty list."
        )

    state = module.params.get("state")

    current_list, _unused, error = client.atp_policy.get_atp_security_exceptions()
    if error:
        module.fail_json(
            msg=f"Error fetching URLs from bypass list: {to_native(error)}"
        )

    current_normalized = normalize_urls(current_list)
    desired_normalized = normalize_urls(bypass_urls)

    module.warn(f"✅ Current list: {current_normalized}")
    module.warn(f"🎯 Desired list: {desired_normalized}")

    changed = False

    if state == "present":
        if desired_normalized != current_normalized:
            changed = True

    elif state == "absent":
        remaining = [url for url in current_normalized if url not in desired_normalized]
        if remaining != current_normalized:
            desired_normalized = remaining
            changed = True
        else:
            desired_normalized = current_normalized

    if module.check_mode:
        module.exit_json(changed=changed)

    if changed:
        updated, _unused, error = client.atp_policy.update_atp_security_exceptions(
            desired_normalized
        )
        if error:
            module.fail_json(
                msg=f"Error updating ATP security exception list: {to_native(error)}"
            )
        module.exit_json(changed=True, security_exceptions=updated)

    module.exit_json(changed=False, security_exceptions=current_list)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        bypass_urls=dict(type="list", elements="str", required=False, no_log=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
