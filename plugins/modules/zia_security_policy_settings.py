#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Technology Alliances, <zscaler-partner-labs@z-bd.com>

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

DOCUMENTATION = """
---
module: zia_security_policy_settings
short_description: "Adds a URL to or removes a URL from the Denylist"
description:
  - Adds a URL to or removes a URL from the Denylist.
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.credentials_set
  - zscaler.ziacloud.fragments.state
options:
  urls:
    description:
        - URLs on the denylist for your organization. Allow up to 25000 URLs.
    type: list
    elements: str
    required: false
  url_type:
    description:
      - The type of URL to be whitelisted or blacklisted.
    required: false
    type: str
    choices:
        - "whitelist"
        - "blacklist"
"""

EXAMPLES = """

- name: ADD and REMOVE URLs from Blacklist or Whitelist
  zscaler.ziacloud.zia_security_policy_settings:
    urls:
      - test1.acme.com
      - test2.acme.com
      - test3.acme.com
      - test4.acme.com
    url_type: "blacklist"
"""

RETURN = """
# The newly whitelisted or blacklisted URL resource record.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    state = module.params.get("state", None)
    urls = module.params.get("urls", [])
    url_type = module.params.get("url_type", "whitelist")

    client = ZIAClientHelper(module)

    security_api = client.security

    if url_type == "whitelist":
        if state == "present":
            current_whitelist = security_api.get_whitelist()
            new_urls = [url for url in urls if url not in current_whitelist]
            if new_urls:
                updated_list = security_api.add_urls_to_whitelist(new_urls)
                module.exit_json(changed=True, whitelist=updated_list)
            else:
                module.exit_json(changed=False, msg="No new URLs to add.")
        elif state == "absent":
            current_whitelist = security_api.get_whitelist()
            urls_to_remove = [url for url in urls if url in current_whitelist]
            if urls_to_remove:
                security_api.delete_urls_from_whitelist(urls_to_remove)
                module.exit_json(changed=True, msg="URLs removed from whitelist.")
            else:
                module.exit_json(changed=False, msg="URLs not in whitelist.")

    elif url_type == "blacklist":
        if state == "present":
            current_blacklist = security_api.get_blacklist()
            new_urls = [url for url in urls if url not in current_blacklist]
            if new_urls:
                updated_list = security_api.add_urls_to_blacklist(new_urls)
                module.exit_json(changed=True, blacklist=updated_list)
            else:
                module.exit_json(changed=False, msg="No new URLs to add.")
        elif state == "absent":
            # Remove URLs from blacklist
            resp_code = security_api.delete_urls_from_blacklist(urls)
            if resp_code == 204:
                module.exit_json(changed=True, msg="URLs removed from blacklist.")
            else:
                module.exit_json(
                    changed=False, msg="Failed to remove URLs from blacklist."
                )


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        urls=dict(type="list", elements="str", required=True),
        url_type=dict(
            type="str", choices=["whitelist", "blacklist"], default="whitelist"
        ),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
