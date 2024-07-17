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
module: zia_rule_labels_info
short_description: "Gets a list of rule labels"
description:
  - "Gets a list of rule labels"
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
    description: "The unique identifier for the rule label."
    type: int
    required: false
  name:
    description: "The rule label name."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets all list of rule label
  zscaler.ziacloud.zia_rule_labels_info:
    provider: '{{ provider }}'

- name: Gets a list of rule label by name
  zscaler.ziacloud.zia_rule_labels_info:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
# Returns information specific Gets rule labels.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    label_id = module.params.get("id", None)
    label_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    labels = []
    if label_id is not None:
        label = client.labels.get_label(label_id).to_dict()
        labels = [label]
    else:
        labels = client.labels.list_labels().to_list()
        if label_name is not None:
            label = None
            for rule in labels:
                if rule.get("name", None) == label_name:
                    label = rule
                    break
            if label is None:
                module.fail_json(
                    msg="Failed to retrieve ip source group: '%s'" % (label_name)
                )
            labels = [label]
    module.exit_json(changed=False, data=labels)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
