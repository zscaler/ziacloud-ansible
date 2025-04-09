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
module: zia_authentication_settings
short_description: Adds or removes URLs authentication exempt list.
description: Adds or removes URLs from the cookie authentication exempt list.
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
  urls:
    description:
        - Domains or URLs which are exempted from SSL Inspection.
    type: list
    elements: str
    required: true
"""

EXAMPLES = """
- name: Create/Update/Delete URLs
  zscaler.ziacloud.zia_authentication_settings:
    urls:
      - .okta.com
      - .oktacdn.com
      - .mtls.oktapreview.com
      - .mtls.okta.com
"""

RETURN = r"""
# The list of exempted URLs.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper


def core(module):
    state = module.params.get("state", None)
    urls = module.params.get("urls", [])

    client = ZIAClientHelper(module)
    auth_settings_api = client.authentication_settings

    # Get current exempted URLs
    current_urls, response, error = auth_settings_api.get_exempted_urls()
    if error:
        module.fail_json(msg=f"Failed to get exempted URLs: {to_native(error)}")

    if state == "present":
        # Filter URLs that aren't already exempted
        new_urls = [url for url in urls if url not in current_urls]

        if new_urls:
            if module.check_mode:
                # Simulate adding URLs without making changes
                module.exit_json(
                    changed=True,
                    msg="URLs would be added.",
                    exempted_urls=current_urls + new_urls,
                )

            # Add new URLs to exempt list
            updated_urls, response, error = auth_settings_api.add_urls_to_exempt_list(new_urls)
            if error:
                module.fail_json(msg=f"Failed to add URLs to exempt list: {to_native(error)}")

            module.exit_json(changed=True, exempted_urls=updated_urls)
        else:
            module.exit_json(changed=False, msg="No new URLs to add.")

    elif state == "absent":
        # Filter URLs that are currently exempted
        urls_to_remove = [url for url in urls if url in current_urls]

        if urls_to_remove:
            if module.check_mode:
                # Simulate removing URLs without making changes
                updated_list = [url for url in current_urls if url not in urls_to_remove]
                module.exit_json(
                    changed=True,
                    msg="URLs would be removed.",
                    exempted_urls=updated_list,
                )

            # Remove URLs from exempt list
            updated_urls, response, error = auth_settings_api.delete_urls_from_exempt_list(urls_to_remove)
            if error:
                module.fail_json(msg=f"Failed to remove URLs from exempt list: {to_native(error)}")

            module.exit_json(changed=True, exempted_urls=updated_urls)
        else:
            module.exit_json(changed=False, msg="URLs not in the exempted list.")


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        urls=dict(type="list", elements="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()