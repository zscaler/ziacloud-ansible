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
module: zia_browser_control_policy_info
short_description: "Gets the Browser Control policy settings"
description:
  - "Retrieves the Browser Control policy settings for the organization."
  - "Browser Control is a singleton resource; there is one policy per organization."
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
"""

EXAMPLES = r"""
- name: Get Browser Control policy settings
  zscaler.ziacloud.zia_browser_control_policy_info:
    provider: '{{ provider }}'
"""

RETURN = r"""
policy:
  description: The Browser Control policy settings.
  returned: always
  type: dict
  contains:
    plugin_check_frequency:
      description:
        - Specifies how frequently the service checks browsers and relevant applications to warn users
          regarding outdated or vulnerable browsers, plugins, and applications.
        - If not set, the warnings are disabled.
      returned: always
      type: str
      sample: "DAILY"
    bypass_plugins:
      description:
        - List of plugins that need to be bypassed for warnings.
        - Has effect only if enable_warnings is true. If not set, all vulnerable plugins are warned.
      returned: always
      type: list
      elements: str
    bypass_applications:
      description:
        - List of applications that need to be bypassed for warnings.
        - Has effect only if enable_warnings is true. If not set, all vulnerable applications are warned.
      returned: always
      type: list
      elements: str
    blocked_internet_explorer_versions:
      description: Versions of Microsoft browser that need to be blocked. If not set, all allowed.
      returned: always
      type: list
      elements: str
    blocked_chrome_versions:
      description: Versions of Google Chrome browser that need to be blocked. If not set, all allowed.
      returned: always
      type: list
      elements: str
    blocked_firefox_versions:
      description: Versions of Mozilla Firefox browser that need to be blocked. If not set, all allowed.
      returned: always
      type: list
      elements: str
    blocked_safari_versions:
      description: Versions of Apple Safari browser that need to be blocked. If not set, all allowed.
      returned: always
      type: list
      elements: str
    blocked_opera_versions:
      description: Versions of Opera browser that need to be blocked. If not set, all allowed.
      returned: always
      type: list
      elements: str
    bypass_all_browsers:
      description: If true, all browsers are bypassed for warnings.
      returned: always
      type: bool
    allow_all_browsers:
      description: If true, allows all browsers and their versions access to the internet.
      returned: always
      type: bool
    enable_warnings:
      description: If true, warnings are enabled.
      returned: always
      type: bool
    enable_smart_browser_isolation:
      description: If true, Smart Browser Isolation is enabled.
      returned: always
      type: bool
    smart_isolation_profile_id:
      description: The isolation profile ID.
      returned: when available
      type: int
    smart_isolation_groups:
      description: List of groups for which the Smart Isolation rule is applied.
      returned: when available
      type: list
      elements: dict
    smart_isolation_users:
      description: List of users for which the Smart Isolation rule is applied.
      returned: when available
      type: list
      elements: dict
    smart_isolation_profile:
      description: The browser isolation profile details.
      returned: when available
      type: dict
      contains:
        id:
          description: The UUID for the browser isolation profile.
          type: str
        name:
          description: Name of the browser isolation profile.
          type: str
        url:
          description: The browser isolation profile URL.
          type: str
        default_profile:
          description: Indicates whether this is a default browser isolation profile.
          type: bool
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    client = ZIAClientHelper(module)

    result, _unused, error = client.browser_control_settings.get_browser_control_settings()
    if error:
        module.fail_json(
            msg=f"Error retrieving Browser Control policy: {to_native(error)}"
        )
    if result is None:
        module.fail_json(msg="Could not read browser control policy settings")

    policy = result.as_dict() if hasattr(result, "as_dict") else result
    module.exit_json(changed=False, policy=policy)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
