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
module: zia_sandbox_advanced_settings_facts
short_description: "Gets the custom list of MD5 file hashes"
description:
  - Gets the custom list of MD5 file hashes that are blocked by Sandbox.
author:
  - William Guilherme (@willguibr)
version_added: "0.1.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
"""

EXAMPLES = r"""
- name: Retrieves the custom list of MD5 file hashes that are blocked by Sandbox.
  zscaler.ziacloud.zia_sandbox_advanced_settings_facts:
    provider: '{{ provider }}'
"""

RETURN = r"""
# Default return values
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    client = ZIAClientHelper(module)

    try:
        # Retrieving the list of MD5 hashes blocked by Sandbox
        behavioral_analysis_data = client.sandbox.get_behavioral_analysis().to_dict()

        # Retrieving the used and unused quota for blocking MD5 file hashes
        file_hash_count_data = client.sandbox.get_file_hash_count().to_dict()

        # Preparing the results to be returned
        results = {
            "behavioral_analysis": behavioral_analysis_data,
            "file_hash_count": file_hash_count_data,
        }

        # Returning the results
        module.exit_json(changed=False, data=results)

    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    core(module)


if __name__ == "__main__":
    main()
