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
module: zia_sandbox_submit
short_description: "Submits a file to the ZIA Advanced Cloud Sandbox for analysis."
description:
  - Submits a file to the ZIA Advanced Cloud Sandbox for analysis.
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
    - zscaler.ziacloud.fragments.credentials_set
    - zscaler.ziacloud.fragments.provider
    - zscaler.ziacloud.fragments.enabled_state
options:
  file_path:
    description: "Path to the file that will be submitted for sandbox analysis."
    type: str
    required: true
  force:
    description: "Force ZIA to analyse the file even if it has been submitted previously."
    type: bool
    default: False
"""

EXAMPLES = """
- name: Submit a file for analysis.
  zscaler.ziacloud.zia_sandbox_submit:
    file_path: "/path/to/malware.exe"
    force: True
"""

RETURN = """
# The Cloud Sandbox submission response information.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    file_path = module.params.get("file_path", "")
    force = module.params.get("force", False)
    inspection_mode = module.params.get(
        "inspection_mode", "sandbox"
    )  # either 'sandbox' or 'out_of_band'

    client = ZIAClientHelper(module)

    sandbox_api = client.sandbox

    if inspection_mode == "sandbox":
        result = sandbox_api.submit_file(file_path, force=force)
    elif inspection_mode == "out_of_band":
        result = sandbox_api.submit_file_for_inspection(file_path)

    if result:
        module.exit_json(changed=True, submission_response=result)
    else:
        module.exit_json(changed=False, msg="Submission failed.")


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        file_path=dict(type="str", required=True),
        force=dict(type="bool", default=False),
        inspection_mode=dict(
            type="str", choices=["sandbox", "out_of_band"], default="sandbox"
        ),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
