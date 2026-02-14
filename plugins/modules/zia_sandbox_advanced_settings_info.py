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
module: zia_sandbox_advanced_settings_info
short_description: "Gets the custom list of MD5 file hashes"
description:
  - Gets the custom list of MD5 file hashes that are blocked by Sandbox.
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
- name: Retrieves the custom list of MD5 file hashes that are blocked by Sandbox.
  zscaler.ziacloud.zia_sandbox_advanced_settings_info:
    provider: '{{ provider }}'
"""

RETURN = r"""
ansible_module_results:
  description: A dictionary containing results returned by the Ansible module.
  returned: always
  type: dict
  contains:
    behavioral_analysis:
      description: Details on behavioral analysis settings related to sandboxing.
      returned: always
      type: dict
      contains:
        file_hashes_to_be_blocked:
          description: List of MD5 file hashes currently configured to be blocked by the sandbox.
          returned: always
          type: list
          elements: str
          sample: ["0316f6067bc02c23c1975d83c659da21", "35e38d023b253c0cd9bd3e16afc362a7", "72fe869aa394ef0a62bb8324857770dd"]
    file_hash_count:
      description: Information about the count of file hashes that are being blocked and the remaining quota.
      returned: always
      type: dict
      contains:
        blocked_file_hashes_count:
          description: The number of file hashes that are currently being blocked.
          returned: always
          type: int
          sample: 3
        remaining_file_hashes:
          description: The remaining quota of file hashes that can still be blocked.
          returned: always
          type: int
          sample: 9997
changed:
  description: A boolean flag that indicates if any changes were made during the execution of the module.
  returned: always
  type: bool
  sample: false
failed:
  description: A boolean flag that indicates if the execution of the module failed.
  returned: always
  type: bool
  sample: false
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
        behavioral_analysis_data, _unused, error1 = client.sandbox.get_behavioral_analysis()
        if error1:
            module.fail_json(msg=f"Error retrieving behavioral analysis: {to_native(error1)}")

        file_hash_count_data, _unused, error2 = client.sandbox.get_file_hash_count()
        if error2:
            module.fail_json(msg=f"Error retrieving file hash count: {to_native(error2)}")

        module.exit_json(
            changed=False,
            behavioral_analysis=(behavioral_analysis_data.as_dict() if hasattr(behavioral_analysis_data, "as_dict") else behavioral_analysis_data),
            file_hash_count=(file_hash_count_data.as_dict() if hasattr(file_hash_count_data, "as_dict") else file_hash_count_data),
        )

    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    core(module)


if __name__ == "__main__":
    main()
