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

DOCUMENTATION = r"""
---
module: zia_activation_status
short_description: "Activates the saved configuration changes."
description: "Activates the saved configuration changes."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  status:
    description:
        - Organization Policy Edit/Update Activation status
    required: true
    type: str
    choices:
        - ACTIVE

  state:
    description:
        - Whether the certificate should be present or absent.
    default: present
    choices: ['present']
    type: str
"""

EXAMPLES = r"""
- name: Activates the saved configuration changes
  zscaler.ziacloud.zia_activation_status:
    provider: '{{ provider }}'
    status: 'ACTIVE'
"""

RETURN = r"""
# Activates the saved configuration changes.
"""

from ansible.module_utils.basic import AnsibleModule
import traceback

# Initialize the variable at the module level
zia_client_import_error = None

try:
    from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
        ZIAClientHelper,
    )
except ImportError as imp_exc:
    ZIAClientHelper = None
    zia_client_import_error = imp_exc


def core(module):
    if ZIAClientHelper is None:
        module.fail_json(
            msg="Failed to import ZIAClientHelper: {}".format(zia_client_import_error)
        )
        return

    client = ZIAClientHelper(module)

    desired_status = module.params.get("status", None)

    # Validate the desired activation status
    if desired_status not in [None, "ACTIVE"]:
        module.fail_json(msg=f"Invalid activation status '{desired_status}'")

    original_activation_status = client.activate.status()

    # If state is 'present' and the desired activation status does not match the current one, attempt to activate
    if module.params.get("state") == "present":
        if original_activation_status != desired_status:
            client.activate.activate()
            new_status = client.activate.status()

            if new_status == "PENDING":
                message = (
                    f"Requested to change status to 'ACTIVE'. However, "
                    f"due to another admin's pending changes, the status remains '{new_status}'. "
                    "Please check with other admins or try again later."
                )
                module.exit_json(
                    changed=False, data={"status": new_status, "message": message}
                )
            else:
                message = f"Status was '{original_activation_status}' and is now '{new_status}'."
                module.exit_json(
                    changed=True, data={"status": new_status, "message": message}
                )
        else:
            message = f"Status remains '{original_activation_status}'."
            module.exit_json(
                changed=False,
                data={"status": original_activation_status, "message": message},
            )
    else:
        module.fail_json(
            msg="State 'absent' is not supported as the API only provides POST and GET methods."
        )

    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec() if ZIAClientHelper else {}
    argument_spec.update(
        status=dict(type="str", choices=["ACTIVE"], required=True),
        state=dict(type="str", choices=["present"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(
            msg="Unhandled exception: {}".format(e), exception=traceback.format_exc()
        )


if __name__ == "__main__":
    main()
