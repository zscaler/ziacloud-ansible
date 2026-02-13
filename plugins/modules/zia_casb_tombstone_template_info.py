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
module: zia_casb_tombstone_template_info
short_description: "Gets information about CASB quarantine tombstone templates"
description:
  - "Gets templates for the tombstone file created when a file is quarantined."
  - "Retrieves a specific template by ID or name."
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
      - The unique identifier for the tombstone template.
    required: false
    type: int
  name:
    description:
      - The name of the tombstone template.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all CASB tombstone templates
  zscaler.ziacloud.zia_casb_tombstone_template_info:
    provider: '{{ provider }}'

- name: Get a tombstone template by ID
  zscaler.ziacloud.zia_casb_tombstone_template_info:
    provider: '{{ provider }}'
    id: 12345

- name: Get a tombstone template by name
  zscaler.ziacloud.zia_casb_tombstone_template_info:
    provider: '{{ provider }}'
    name: "Default Tombstone"
"""

RETURN = r"""
templates:
  description: A list of quarantine tombstone templates fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the tombstone template.
      returned: always
      type: int
    name:
      description: The name of the tombstone template.
      returned: always
      type: str
    description:
      description: The text included in the tombstone file.
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
    template_id = module.params.get("id")
    template_name = module.params.get("name")

    client = ZIAClientHelper(module)
    result, _unused, error = (
        client.saas_security_api.list_quarantine_tombstone_lite()
    )
    if error:
        module.fail_json(
            msg=f"Error retrieving tombstone templates: {to_native(error)}"
        )
    templates_list = [t.as_dict() for t in result] if result else []

    matched = None
    for t in templates_list:
        if template_id is not None and t.get("id") == template_id:
            matched = t
            break
        if template_name and t.get("name") == template_name:
            matched = t
            break

    if template_id is not None or template_name:
        if matched is None:
            module.fail_json(
                msg=f"Tombstone template with name '{template_name}' or id '{template_id}' not found. "
                "Omit id and name to list all templates."
            )
        templates_out = [matched]
    else:
        templates_out = templates_list

    module.exit_json(changed=False, templates=templates_out)


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
