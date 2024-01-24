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
module: zia_activation_status_facts
short_description: "Gets the activation status."
description: "Gets the activation status for the saved configuration changes."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.credentials_set
options:
  status:
    description:
        - Organization Policy Edit/Update Activation status
    required: false
    type: str
    choices:
        - "ACTIVE"
        - "PENDING"
        - "INPROGRESS"
"""

EXAMPLES = """
- name: Gets the activation status for the saved configuration changes
  zscaler.ziacloud.zia_activation_status:
    status: "ACTIVE"
"""

RETURN = """
# Gets the activation status for the saved configuration changes.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    activation_status = module.params.get("status", None)
    client = ZIAClientHelper(module)

    current_activation_status = client.config.activate()

    # If specific status provided, check if it matches the current activation status
    if activation_status:
        if current_activation_status == activation_status:
            module.exit_json(
                changed=False, data=current_activation_status, status_matches=True
            )
        else:
            module.exit_json(
                changed=False,
                data=current_activation_status,
                status_matches=False,
                msg=f"Provided status '{activation_status}' does not match the current activation status '{current_activation_status}'",
            )
    else:
        module.exit_json(changed=False, data=current_activation_status)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        status=dict(type="str", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
