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
module: zia_casb_email_label_info
short_description: "Gets information about CASB email labels"
description:
  - "Gets email labels generated for the SaaS Security API policies in a user's email account."
  - "Retrieves a specific label by ID or name."
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

options:
  id:
    description:
      - The unique identifier for the CASB email label.
    required: false
    type: int
  name:
    description:
      - The name of the CASB email label.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all CASB email labels
  zscaler.ziacloud.zia_casb_email_label_info:
    provider: '{{ provider }}'

- name: Get a CASB email label by ID
  zscaler.ziacloud.zia_casb_email_label_info:
    provider: '{{ provider }}'
    id: 12345

- name: Get a CASB email label by name
  zscaler.ziacloud.zia_casb_email_label_info:
    provider: '{{ provider }}'
    name: "My Email Label"
"""

RETURN = r"""
labels:
  description: A list of CASB email labels fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the CASB email label.
      returned: always
      type: int
    name:
      description: The name of the email label.
      returned: always
      type: str
    label_deleted:
      description: Whether the label has been deleted.
      returned: when available
      type: bool
    label_desc:
      description: Description of the email label.
      returned: when available
      type: str
    label_color:
      description: Color applied to the email label.
      returned: when available
      type: str
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    label_id = module.params.get("id")
    label_name = module.params.get("name")

    client = ZIAClientHelper(module)

    result, _unused, error = client.saas_security_api.list_casb_email_label_lite()
    if error:
        module.fail_json(
            msg=f"Error retrieving CASB email labels: {to_native(error)}"
        )
    labels_list = [lbl.as_dict() for lbl in result] if result else []

    matched = None
    for lbl in labels_list:
        if label_id is not None and lbl.get("id") == label_id:
            matched = lbl
            break
        if label_name and lbl.get("name") == label_name:
            matched = lbl
            break

    if label_id is not None or label_name:
        if matched is None:
            module.fail_json(
                msg=f"CASB email label with name '{label_name}' or id '{label_id}' not found. "
                "Omit id and name to list all labels."
            )
        labels_out = [matched]
    else:
        labels_out = labels_list

    module.exit_json(changed=False, labels=labels_out)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
