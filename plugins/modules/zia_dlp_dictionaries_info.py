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
dictionaries:
  description: Details about the DLP dictionaries retrieved.
  returned: when successful
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier of the DLP dictionary.
      returned: always
      type: int
      sample: 1
    name:
      description: The name of the DLP dictionary.
      returned: always
      type: str
      sample: "Example_Dictionary"
    description:
      description: Description of the DLP dictionary.
      returned: always
      type: str
      sample: "Example_Dictionary"
    custom:
      description: Indicates whether the dictionary is custom.
      returned: always
      type: bool
      sample: true
    dictionary_type:
      description: Type of the dictionary, indicating whether it contains patterns, phrases, or both.
      returned: always
      type: str
      sample: "PATTERNS_AND_PHRASES"
    custom_phrase_match_type:
      description: Describes the phrase match type for the dictionary.
      returned: always
      type: str
      sample: "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
    custom_phrase_supported:
      description: Indicates if custom phrases are supported in this dictionary.
      returned: always
      type: bool
      sample: false
    dictionary_cloning_enabled:
      description: Indicates if cloning of the dictionary is enabled.
      returned: always
      type: bool
      sample: false
    patterns:
      description: List of patterns included in the dictionary.
      returned: always
      type: list
      elements: dict
      contains:
        pattern:
          description: The regex pattern included in the dictionary.
          returned: always
          type: str
          sample: "test"
        action:
          description: The action associated with the pattern.
          returned: always
          type: str
          sample: "PATTERN_COUNT_TYPE_UNIQUE"
    phrases:
      description: List of phrases included in the dictionary.
      returned: always
      type: list
      elements: dict
      contains:
        phrase:
          description: The phrase included in the dictionary.
          returned: always
          type: str
          sample: "test"
        action:
          description: The action associated with the phrase.
          returned: always
          type: str
          sample: "PHRASE_COUNT_TYPE_ALL"
"""


from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    dict_id = module.params.get("id")
    dict_name = module.params.get("name")

    client = ZIAClientHelper(module)
    dictionaries = []

    if dict_id is not None:
        dict_obj, _unused, error = client.dlp_dictionary.get_dict(dict_id)
        if error or dict_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve DLP Dictionary with ID '{dict_id}': {to_native(error)}"
            )
        dictionaries = [dict_obj.as_dict()]
    else:
        query_params = {}
        if dict_name:
            query_params["search"] = dict_name

        result, _unused, error = client.dlp_dictionary.list_dicts(
            query_params=query_params
        )
        if error:
            module.fail_json(
                msg=f"Error retrieving DLP Dictionaries: {to_native(error)}"
            )

        dict_list = [d.as_dict() for d in result] if result else []

        if dict_name:
            matched = next((d for d in dict_list if d.get("name") == dict_name), None)
            if not matched:
                available = [d.get("name") for d in dict_list]
                module.fail_json(
                    msg=f"DLP Dictionary named '{dict_name}' not found. Available: {available}"
                )
            dictionaries = [matched]
        else:
            dictionaries = dict_list

    module.exit_json(changed=False, dictionaries=dictionaries)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["name", "id"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
