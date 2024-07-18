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
module: zia_dlp_dictionaries_info
short_description: "Custom and predefined DLP dictionaries."
description: "Gets information on all custom and predefined DLP dictionaries."
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
    description: "Unique identifier for the DLP dictionary"
    type: int
  name:
    description: "Name of the DLP dictionary's name"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all ZIA DLP Dictionaries
  zscaler.ziacloud.zia_dlp_dictionaries_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a ZIA DLP Dictionaries by Name
  zscaler.ziacloud.zia_dlp_dictionaries_info:
    provider: '{{ provider }}'
    name: "Example"
"""

RETURN = r"""
# Returns information on a specified ZIA DLP Dictionaries.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    dict_id = module.params.get("id", None)
    dict_name = module.params.get("name", None)
    client = ZIAClientHelper(module)

    dictionaries = []
    if dict_id is not None:
        dictionary = client.dlp.get_dict(dict_id).to_dict()
        dictionaries = [dictionary]
    else:
        dictionaries = client.dlp.list_dicts().to_list()
        if dict_name is not None:
            dictionary = None
            for dict in dictionaries:
                if dict.get("name", None) == dict_name:
                    dictionary = dict
                    break
            if dictionary is None:
                module.fail_json(
                    msg="Failed to retrieve dlp dictionary: '%s'" % (dict_name)
                )
            dictionaries = [dictionary]
    module.exit_json(changed=False, dictionaries=dictionaries)


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
