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
module: zia_remote_assistance_info
short_description: Retrieves information about the Remote Assistance option configured in the ZIA Admin Portal
description: Retrieves information about the Remote Assistance option configured in the ZIA Admin Portal
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

options: {}
"""

EXAMPLES = r"""
- name: Retrieves browser-based end user notification
  zscaler.ziacloud.zia_remote_assistance_info:
    provider: '{{ provider }}'
"""

RETURN = r"""
remote_assistance:
  description: Browser-based End User Notification (EUN) configuration settings.
  returned: always
  type: dict
  contains:
    view_only_until:
      description: Unix timestamp until which view-only access is allowed
      returned: always
      type: int
      sample: 1734144119000
    full_access_until:
      description: Unix timestamp until which full access is allowed
      returned: always
      type: int
      sample: 1734144119000
    username_obfuscated:
      description: Whether usernames for SSO users are obfuscated
      returned: always
      type: bool
      sample: true
    device_info_obfuscate:
      description: Whether device info (hostname, name, owner) is hidden in UI
      returned: always
      type: bool
      sample: true
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    client = ZIAClientHelper(module)

    remote_assistance, _unused, error = client.remote_assistance.get_remote_assistance()
    if error:
        module.fail_json(msg=f"Error fetching remote assistance: {to_native(error)}")

    module.exit_json(changed=False, remote_assistance=remote_assistance.as_dict())


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
