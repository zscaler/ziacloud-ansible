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
module: zia_security_policy_settings
short_description: "Adds a URL to or removes a URL from the Denylist"
description:
  - Adds a URL to or removes a URL from the Denylist.
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
  urls:
    description:
        - URLs on the denylist for your organization. Allow up to 25000 URLs.
    type: list
    elements: str
    required: true
  url_type:
    description:
      - The type of URL to be whitelisted or blacklisted.
    required: false
    type: str
    default: whitelist
    choices:
        - whitelist
        - blacklist
"""

EXAMPLES = r"""

- name: ADD and REMOVE URLs from Blacklist or Whitelist
  zscaler.ziacloud.zia_security_policy_settings:
    provider: '{{ provider }}'
    urls:
      - test1.acme.com
      - test2.acme.com
      - test3.acme.com
      - test4.acme.com
    url_type: "blacklist"
"""

RETURN = r"""
# The newly whitelisted or blacklisted URL resource record.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_urls(urls):
    """Normalize URLs for comparison by sorting and lowercasing."""
    return sorted(set(url.strip().lower() for url in urls if url))


def core(module):
    state = module.params.get("state", None)
    urls = module.params.get("urls", [])
    url_type = module.params.get("url_type", "whitelist")

    client = ZIAClientHelper(module)

    # Normalize desired list
    desired_urls = normalize_urls(urls)

    # Fetch current list
    if url_type == "whitelist":
        current_obj, _unused, error = client.security_policy_settings.get_whitelist()
        if error or not current_obj:
            module.fail_json(msg=f"Failed to fetch whitelist: {to_native(error)}")
        current_urls = normalize_urls(current_obj.whitelist_urls)
    else:
        current_obj, _unused, error = client.security_policy_settings.get_blacklist()
        if error or not current_obj:
            module.fail_json(msg=f"Failed to fetch blacklist: {to_native(error)}")
        current_urls = normalize_urls(current_obj.blacklist_urls)

    module.warn(f"🔍 Current {url_type}: {current_urls}")
    module.warn(f"📥 Desired {url_type}: {desired_urls}")

    # Determine changes
    urls_to_add = [u for u in desired_urls if u not in current_urls]
    urls_to_remove = (
        [u for u in current_urls if u in desired_urls] if state == "absent" else []
    )

    if module.check_mode:
        if (state == "present" and urls_to_add) or (
            state == "absent" and urls_to_remove
        ):
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    # Perform updates
    if state == "present" and urls_to_add:
        if url_type == "whitelist":
            updated_obj, _unused, error = (
                client.security_policy_settings.add_urls_to_whitelist(urls_to_add)
            )
        else:
            updated_obj, _unused, error = (
                client.security_policy_settings.add_urls_to_blacklist(urls_to_add)
            )

        if error:
            module.fail_json(msg=f"Failed to add URLs: {to_native(error)}")

        updated_urls = normalize_urls(
            updated_obj.whitelist_urls
            if url_type == "whitelist"
            else updated_obj.blacklist_urls
        )
        module.exit_json(changed=True, updated_list=updated_urls)

    elif state == "absent" and urls_to_remove:
        if url_type == "whitelist":
            updated_obj, _unused, error = (
                client.security_policy_settings.delete_urls_from_whitelist(
                    urls_to_remove
                )
            )
        else:
            updated_obj, _unused, error = (
                client.security_policy_settings.delete_urls_from_blacklist(
                    urls_to_remove
                )
            )

        if error:
            module.fail_json(msg=f"Failed to remove URLs: {to_native(error)}")

        updated_urls = normalize_urls(
            updated_obj.whitelist_urls
            if url_type == "whitelist"
            else updated_obj.blacklist_urls
        )
        module.exit_json(changed=True, updated_list=updated_urls)

    module.exit_json(changed=False, msg="No updates were necessary.")


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        urls=dict(type="list", elements="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
        url_type=dict(
            type="str", choices=["whitelist", "blacklist"], default="whitelist"
        ),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
