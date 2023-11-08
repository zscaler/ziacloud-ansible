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
module: zia_dlp_dictionaries
short_description: "Adds a new custom DLP dictionary."
description:
  - "Create a new custom DLP dictionary."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
options:
  username:
    description: "Username of admin user that is provisioned"
    required: true
    type: str
  password:
    description: "Password of the admin user"
    required: true
    type: str
  api_key:
    description: "The obfuscated form of the API key"
    required: true
    type: str
  base_url:
    description: "The host and basePath for the cloud services API"
    required: true
    type: str
  id:
    description: "Unique identifier for the DLP dictionary"
    required: false
    type: int
  name:
    description: "The DLP dictionary's name"
    required: true
    type: str
  description:
    description: "The description of the DLP dictionary"
    required: false
    type: str
  match_type:
    description: ""
    required: false
    type: str
  confidence_threshold:
    description:
        - The DLP confidence threshold
    required: false
    type: str
    choices:
      - CONFIDENCE_LEVEL_LOW
      - CONFIDENCE_LEVEL_MEDIUM
      - CONFIDENCE_LEVEL_HIGH
  phrases:
    type: list
    elements: dict
    description:
      - List containing the phrases used within a custom DLP dictionary. This attribute is not applicable to predefined DLP dictionaries.
    required: false
    suboptions:
      action:
        type: str
        required: false
        description:
          - The action applied to a DLP dictionary using phrases.
        choices:
          - PHRASE_COUNT_TYPE_UNIQUE
          - PHRASE_COUNT_TYPE_ALL
      phrase:
        type: str
        required: false
        description:
          - DLP dictionary phrase.
  custom_phrase_match_type:
    description:
        - The DLP confidence threshold
    required: false
    type: str
    choices:
      - MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY
      - MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY
  patterns:
    type: list
    elements: dict
    description:
      - List containing the patterns used within a custom DLP dictionary. This attribute is not applicable to predefined DLP dictionaries
    required: false
    suboptions:
      action:
        type: str
        required: false
        description:
          - The action applied to a DLP dictionary using patterns.
        choices:
          - PATTERN_COUNT_TYPE_ALL
          - PATTERN_COUNT_TYPE_UNIQUE
      pattern:
        type: str
        required: false
        description:
          - DLP dictionary pattern.
  name_l10n_tag:
    description:
      - Indicates whether the name is localized or not. This is always set to True for predefined DLP dictionaries.
    required: false
    type: bool
  threshold_type:
    description:
        - DLP threshold type
    required: false
    type: str
    choices:
      - VIOLATION_COUNT_ONLY
      - CONFIDENCE_SCORE_ONLY
      - VIOLATION_AND_CONFIDENCE
  dictionary_type:
    description:
        - DLP threshold type
    required: false
    type: str
    choices:
      - PATTERNS_AND_PHRASES
      - EXACT_DATA_MATCH
      - INDEXED_DATA_MATCH
  exact_data_match_details:
    type: list
    elements: dict
    description:
      - Exact Data Match (EDM) related information for custom DLP dictionaries.
    required: false
    suboptions:
      dictionary_edm_mapping_id:
        type: int
        required: false
        description:
          - The unique identifier for the EDM mapping.
      schema_id:
        type: int
        required: false
        description:
          - The unique identifier for the EDM template (or schema).
      primary_field:
        type: int
        required: false
        description:
          - The EDM template's primary field.
      secondary_fields:
        type: int
        required: false
        description:
          - The EDM template's secondary fields.
      secondary_field_match_on:
        type: str
        required: false
        description:
          - The EDM secondary field to match on.
        choices:
          - MATCHON_NONE, MATCHON_ANY_1, MATCHON_ANY_2, MATCHON_ANY_3, MATCHON_ANY_4
          - MATCHON_ANY_5, MATCHON_ANY_6, MATCHON_ANY_7, MATCHON_ANY_8, MATCHON_ANY_9
          - MATCHON_ANY_10, MATCHON_ANY_11, MATCHON_ANY_12, MATCHON_ANY_13, MATCHON_ANY_14
          - MATCHON_ANY_15, MATCHON_ALL
  idm_profile_match_accuracy:
    type: list
    elements: dict
    description:
      - Exact Data Match (EDM) related information for custom DLP dictionaries.
    required: false
    suboptions:
      adp_idm_profile:
        type: int
        required: false
        description:
          - The IDM template reference.
        suboptions:
          id:
            type: int
            required: false
            description:
              - Identifier that uniquely identifies an entity.
      match_accuracy:
        type: str
        required: false
        description:
          - The IDM template match accuracy.
        choices:
          - LOW
          - MEDIUM
          - HEAVY
  proximity:
    description:
      - The DLP dictionary proximity length.
    required: false
    type: int
  custom:
    description:
      - This value is set to true for custom DLP dictionaries.
    required: false
    type: bool
  proximity_length_enabled:
    description:
      - This value is set to true if proximity length and high confidence phrases are enabled for the DLP dictionary
    required: false
    type: bool
"""

EXAMPLES = """

- name: Create/Update/Delete dlp dictionary.
  zscaler.ziacloud.zia_dlp_dictionaries:
    name: "Ansible_Test"
    description: "Ansible_Test"
    dictionary_type: "PATTERNS_AND_PHRASES"
    custom_phrase_match_type: "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
    match_type: "all"
    phrases:
      - action: "PHRASE_COUNT_TYPE_UNIQUE"
        phrase: "YourPhrase"
    patterns:
      - action: "PATTERN_COUNT_TYPE_ALL"
        pattern: "YourPattern"
"""

RETURN = """
# The newly created DLP Dictionary record.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    deleteNone,
    zia_argument_spec,
)
from zscaler import ZIA


def core(module):
    state = module.params.get("state", None)
    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )
    dictionary = dict()
    params = [
        "id",
        "name",
        "description",
        "confidence_threshold",
        "phrases",
        "custom_phrase_match_type",
        "patterns",
        "name_l10n_tag",
        "threshold_type",
        "dictionary_type",
        "exact_data_match_details",
        "idm_profile_match_accuracy",
        "proximity",
        "custom",
        "proximity_length_enabled",
        "match_type",
    ]
    for param_name in params:
        dictionary[param_name] = module.params.get(param_name, None)
    dict_id = dictionary.get("id", None)
    dict_name = dictionary.get("name", None)
    existing_dictionary = None
    if dict_id is not None:
        dictBox = client.dlp.get_dict(dict_id=dict_id)
        if dictBox is not None:
            existing_dictionary = dictBox.to_dict()
    elif dict_name is not None:
        dictionaries = client.dlp.list_dicts().to_list()
        for dictionary_ in dictionaries:
            if dictionary_.get("name") == dict_name:
                existing_dictionary = dictionary_
    if existing_dictionary is not None:
        id = existing_dictionary.get("id")
        existing_dictionary.update(dictionary)
        existing_dictionary["id"] = id
    if state == "present":
        if existing_dictionary is not None:
            """Update"""
            existing_dictionary = deleteNone(
                dict(
                    dict_id=existing_dictionary.get("id", ""),
                    name=existing_dictionary.get("name", ""),
                    description=existing_dictionary.get("description", ""),
                    confidence_threshold=existing_dictionary.get(
                        "confidence_threshold", ""
                    ),
                    phrases=existing_dictionary.get("phrases", ""),
                    custom_phrase_match_type=existing_dictionary.get(
                        "custom_phrase_match_type", ""
                    ),
                    patterns=existing_dictionary.get("patterns", ""),
                    name_l10n_tag=existing_dictionary.get("name_l10n_tag", ""),
                    threshold_type=existing_dictionary.get("threshold_type", ""),
                    dictionary_type=existing_dictionary.get("dictionary_type", ""),
                    exact_data_match_details=existing_dictionary.get(
                        "exact_data_match_details", ""
                    ),
                    idm_profile_match_accuracy=existing_dictionary.get(
                        "idm_profile_match_accuracy", ""
                    ),
                    proximity=existing_dictionary.get("proximity", ""),
                    custom=existing_dictionary.get("custom", ""),
                    match_type=existing_dictionary.get("match_type", ""),
                    proximity_length_enabled=existing_dictionary.get(
                        "proximity_length_enabled", ""
                    ),
                )
            )
            existing_dictionary = client.dlp.update_dict(
                **existing_dictionary
            ).to_dict()
            module.exit_json(changed=True, data=existing_dictionary)
        else:
            """Create"""
            dictionary = deleteNone(
                dict(
                    name=dictionary.get("name", ""),
                    description=dictionary.get("description", ""),
                    confidence_threshold=dictionary.get("confidence_threshold", ""),
                    phrases=dictionary.get("phrases", ""),
                    custom_phrase_match_type=dictionary.get(
                        "custom_phrase_match_type", ""
                    ),
                    patterns=dictionary.get("patterns", ""),
                    name_l10n_tag=dictionary.get("name_l10n_tag", ""),
                    threshold_type=dictionary.get("threshold_type", ""),
                    dictionary_type=dictionary.get("dictionary_type", ""),
                    exact_data_match_details=dictionary.get(
                        "exact_data_match_details", ""
                    ),
                    idm_profile_match_accuracy=dictionary.get(
                        "idm_profile_match_accuracy", ""
                    ),
                    proximity=dictionary.get("proximity", ""),
                    custom=dictionary.get("custom", ""),
                    match_type=dictionary.get("match_type", ""),
                    proximity_length_enabled=dictionary.get(
                        "proximity_length_enabled", ""
                    ),
                )
            )
            dictionary = client.dlp.add_dict(**dictionary).to_dict()
            module.exit_json(changed=True, data=dictionary)
    elif state == "absent":
        if existing_dictionary is not None:
            code = client.dlp.delete_dict(dict_id=existing_dictionary.get("id"))
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_dictionary)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = zia_argument_spec()
    id_spec = dict(
        type="list",
        elements="str",
        required=False,
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        match_type=dict(type="str", required=False),
        description=dict(type="str", required=False),
        confidence_threshold=dict(
            type="str",
            required=False,
            choices=[
                "CONFIDENCE_LEVEL_LOW",
                "CONFIDENCE_LEVEL_MEDIUM",
                "CONFIDENCE_LEVEL_HIGH",
            ],
        ),
        phrases=dict(
            type="list",
            elements="dict",
            options=dict(
                action=dict(
                    type="str",
                    choices=["PHRASE_COUNT_TYPE_UNIQUE", "PHRASE_COUNT_TYPE_ALL"],
                ),
                phrase=dict(type="str", required=False),
            ),
            required=False,
        ),
        custom_phrase_match_type=dict(
            type="str",
            required=False,
            choices=[
                "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY",
                "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
            ],
        ),
        patterns=dict(
            type="list",
            elements="dict",
            options=dict(
                action=dict(
                    type="str",
                    choices=["PATTERN_COUNT_TYPE_ALL", "PATTERN_COUNT_TYPE_UNIQUE"],
                ),
                phrase=dict(type="str", required=False),
            ),
            required=False,
        ),
        name_l10n_tag=dict(
            type="bool",
            required=False,
        ),
        threshold_type=dict(
            type="str",
            required=False,
            choices=[
                "VIOLATION_COUNT_ONLY",
                "CONFIDENCE_SCORE_ONLY",
                "VIOLATION_AND_CONFIDENCE",
            ],
        ),
        dictionary_type=dict(
            type="str",
            required=False,
            choices=["PATTERNS_AND_PHRASES", "EXACT_DATA_MATCH", "INDEXED_DATA_MATCH"],
        ),
        exact_data_match_details=dict(
            type="list",
            elements="dict",
            options=dict(
                dictionary_edm_mapping_id=dict(type="int", required=False),
                schema_id=dict(type="int", required=False),
                primary_field=dict(type="int", required=False),
                secondary_fields=dict(type="list", elements="str", required=False),
                secondary_field_match_on=dict(
                    type="str",
                    required=False,
                    choices=[
                        "MATCHON_NONE",
                        "MATCHON_ANY_1",
                        "MATCHON_ANY_2",
                        "MATCHON_ANY_3",
                        "MATCHON_ANY_4",
                        "MATCHON_ANY_5",
                        "MATCHON_ANY_6",
                        "MATCHON_ANY_7",
                        "MATCHON_ANY_8",
                        "MATCHON_ANY_9",
                        "MATCHON_ANY_10",
                        "MATCHON_ANY_11",
                        "MATCHON_ANY_12",
                        "MATCHON_ANY_13",
                        "MATCHON_ANY_14",
                        "MATCHON_ANY_15",
                        "MATCHON_ALL",
                    ],
                ),
            ),
            required=False,
        ),
        idm_profile_match_accuracy=dict(
            type="list",
            elements="dict",
            options=dict(
                adp_idm_profile=id_spec,
                match_accuracy=dict(type="str", choices=["LOW", "MEDIUM", "HEAVY"]),
            ),
            required=False,
        ),
        proximity=dict(type="int", required=False),
        custom=dict(type="bool", required=False),
        proximity_length_enabled=dict(type="bool", required=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
