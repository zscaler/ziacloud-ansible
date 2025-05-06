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
module: zia_dlp_dictionaries
short_description: "Adds a new custom DLP dictionary."
description:
  - "Create a new custom DLP dictionary."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
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
  confidence_threshold:
    description:
        - The DLP confidence threshold
    required: false
    type: str
    choices:
      - CONFIDENCE_LEVEL_LOW
      - CONFIDENCE_LEVEL_MEDIUM
      - CONFIDENCE_LEVEL_HIGH
  predefined_count_action_type:
    description:
        - This field specifies whether duplicate matches of a phrase from a dictionary must be counted individually
        - or toward the match count or ignored, thereby maintaining a single count for multiple occurrences.
    required: false
    type: str
    choices:
      - PHRASE_COUNT_TYPE_UNIQUE
      - PHRASE_COUNT_TYPE_ALL
  phrases:
    type: list
    elements: dict
    description:
      - List containing the phrases used within a custom DLP dictionary.
    required: false
    suboptions:
      action:
        type: str
        required: true
        description:
          - The action applied to a DLP dictionary using phrases.
        choices:
          - PHRASE_COUNT_TYPE_UNIQUE
          - PHRASE_COUNT_TYPE_ALL
      phrase:
        type: str
        required: true
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
      - List containing the patterns used within a custom DLP dictionary.
    required: false
    suboptions:
      action:
        type: str
        required: true
        description:
          - The action applied to a DLP dictionary using patterns.
        choices:
          - PATTERN_COUNT_TYPE_ALL
          - PATTERN_COUNT_TYPE_UNIQUE
      pattern:
        type: str
        required: true
        description:
          - DLP dictionary pattern.
  dictionary_type:
    description:
        - The DLP dictionary type.
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
        type: list
        elements: int
        required: false
        description:
          - The EDM template's secondary fields.
      secondary_field_match_on:
        type: list
        elements: str
        required: false
        description:
          - The EDM secondary field to match on.
        choices:
          - MATCHON_NONE
          - MATCHON_ANY_1
          - MATCHON_ANY_2
          - MATCHON_ANY_3
          - MATCHON_ANY_4
          - MATCHON_ANY_5
          - MATCHON_ANY_6
          - MATCHON_ANY_7
          - MATCHON_ANY_8
          - MATCHON_ANY_9
          - MATCHON_ANY_10
          - MATCHON_ANY_11
          - MATCHON_ANY_12
          - MATCHON_ANY_13
          - MATCHON_ANY_14
          - MATCHON_ANY_15
          - MATCHON_ALL
  idm_profile_match_accuracy:
    type: list
    elements: dict
    description:
      - Exact Data Match (EDM) related information for custom DLP dictionaries.
    required: false
    suboptions:
      adp_idm_profile:
        type: list
        elements: int
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
  ignore_exact_match_idm_dict:
    description:
      - Indicates whether to exclude documents that are a 100% match to already-indexed documents from triggering an Indexed Document Match (IDM) Dictionary.
    required: false
    type: bool
  include_bin_numbers:
    description:
      - A true value denotes that the specified Bank Identification Number (BIN) values are included in the Credit Cards dictionary.
      - A false value denotes that the specified BIN values are excluded from the Credit Cards dictionary.
    required: false
    type: bool
  bin_numbers:
    description:
      - The list of Bank Identification Number (BIN) values that are included or excluded from the Credit Cards dictionary.
      - BIN values can be specified only for Diners Club, Mastercard, RuPay, and Visa cards.
      - Up to 512 BIN values can be configured in a dictionary.
    type: list
    elements: str
    required: false
  dict_template_id:
    description:
      - ID of the predefined dictionary (original source dictionary) that is used for cloning.
      - This field is applicable only to cloned dictionaries.
      - Only a limited set of identification-based predefined dictionaries
      - (e.g., Credit Cards, Social Security Numbers, National Identification Numbers, etc.) can be cloned.
      - Up to 4 clones can be created from a predefined dictionary.
    required: false
    type: int
  proximity:
    description:
      - The DLP dictionary proximity length.
    required: false
    type: int
"""

EXAMPLES = r"""
- name: Create/Update/Delete dlp dictionary.
  zscaler.ziacloud.zia_dlp_dictionaries:
    provider: '{{ provider }}'
    name: "Example_Dictionary"
    description: "Example_Dictionary"
    custom_phrase_match_type: "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
    dictionary_type: "PATTERNS_AND_PHRASES"
    phrases:
      - action: "PHRASE_COUNT_TYPE_UNIQUE"
        phrase: "YourPhrase"
    patterns:
      - action: "PATTERN_COUNT_TYPE_ALL"
        pattern: "YourPattern"
"""

RETURN = r"""
# The newly created DLP Dictionary record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import deleteNone
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_phrases_patterns(data):
    """Normalize phrases/patterns to comparable format (tuples)"""
    if isinstance(data, list):
        normalized = []
        for item in data:
            if isinstance(item, dict):
                # Convert dict to tuple
                if "phrase" in item:
                    normalized.append((item["action"], item["phrase"]))
                elif "pattern" in item:
                    normalized.append((item["action"], item["pattern"]))
            elif isinstance(item, (tuple, list)) and len(item) == 2:
                # Already in tuple format
                normalized.append(tuple(item))
        return normalized
    return data


def normalize_dict(dict_):
    normalized = dict_.copy() if dict_ else {}
    for attr in [
        "id",
        "exact_data_match_details",
        "ignore_exact_match_idm_dict",
        "include_bin_numbers",
        "dict_template_id",
        "proximity",
    ]:
        normalized.pop(attr, None)

    # Normalize phrases and patterns if they exist
    if "phrases" in normalized:
        normalized["phrases"] = normalize_phrases_patterns(normalized["phrases"])
    if "patterns" in normalized:
        normalized["patterns"] = normalize_phrases_patterns(normalized["patterns"])

    return normalized


def transform_phrases_patterns(dictionary):
    """Transform phrases and patterns from dict format to tuple format expected by SDK"""
    transformed = dictionary.copy()

    if "phrases" in transformed and isinstance(transformed["phrases"], list):
        transformed["phrases"] = [
            (phrase["action"], phrase["phrase"])
            for phrase in transformed["phrases"]
            if isinstance(phrase, dict) and "action" in phrase and "phrase" in phrase
        ]

    if "patterns" in transformed and isinstance(transformed["patterns"], list):
        transformed["patterns"] = [
            (pattern["action"], pattern["pattern"])
            for pattern in transformed["patterns"]
            if isinstance(pattern, dict)
            and "action" in pattern
            and "pattern" in pattern
        ]

    return transformed


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    params = [
        "id",
        "name",
        "description",
        "confidence_threshold",
        "predefined_count_action_type",
        "custom_phrase_match_type",
        "dictionary_type",
        "patterns",
        "phrases",
        "exact_data_match_details",
        "idm_profile_match_accuracy",
        "ignore_exact_match_idm_dict",
        "include_bin_numbers",
        "bin_numbers",
        "dict_template_id",
        "proximity",
    ]

    dictionary = {param: module.params.get(param) for param in params}
    dictionary = transform_phrases_patterns(dictionary)
    dict_id = dictionary.get("id")
    existing_dict = None

    if dict_id:
        result, _unused, error = client.dlp_dictionary.get_dict(dict_id)
        if error:
            module.fail_json(
                msg=f"Error fetching dictionary ID {dict_id}: {to_native(error)}"
            )
        existing_dict = result.as_dict() if result else None
    else:
        result, _unused, error = client.dlp_dictionary.list_dicts()
        if error:
            module.fail_json(msg=f"Error listing dictionaries: {to_native(error)}")
        for item in result:
            if item.name == dictionary.get("name"):
                existing_dict = item.as_dict()
                break

    # NEW: Normalize both desired and current states
    desired = normalize_dict(dictionary)
    current = normalize_dict(existing_dict) if existing_dict else {}

    # NEW: Handle custom field explicitly if not specified
    if "custom" not in dictionary:
        desired.pop("custom", None)
        current.pop("custom", None)

    # Enhanced drift detection
    changed_fields = {}
    for key in desired:
        if desired.get(key) != current.get(key):
            changed_fields[key] = {
                "desired": desired.get(key),
                "current": current.get(key),
            }

    if changed_fields:
        module.warn("Drift detected in the following fields:")
        for field, values in changed_fields.items():
            module.warn(f"  {field}:")
            module.warn(f"    Desired: {values['desired']}")
            module.warn(f"    Current: {values['current']}")
    else:
        module.warn("No drift detected - all fields match current state")

    changed = bool(changed_fields)

    if module.check_mode:
        if state == "present" and (existing_dict is None or changed):
            module.exit_json(changed=True, drift_details=changed_fields)
        elif state == "absent" and existing_dict:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_dict:
            if changed:
                update_data = deleteNone(
                    {
                        "dict_id": existing_dict["id"],
                        "name": dictionary.get("name"),
                        "description": dictionary.get("description"),
                        "confidence_threshold": dictionary.get("confidence_threshold"),
                        "predefined_count_action_type": dictionary.get(
                            "predefined_count_action_type"
                        ),
                        "custom_phrase_match_type": dictionary.get(
                            "custom_phrase_match_type"
                        ),
                        "dictionary_type": dictionary.get("dictionary_type"),
                        "patterns": dictionary.get("patterns"),
                        "phrases": dictionary.get("phrases"),
                        "exact_data_match_details": dictionary.get(
                            "exact_data_match_details"
                        ),
                        "idm_profile_match_accuracy": dictionary.get(
                            "idm_profile_match_accuracy"
                        ),
                        "ignore_exact_match_idm_dict": dictionary.get(
                            "ignore_exact_match_idm_dict"
                        ),
                        "include_bin_numbers": dictionary.get("include_bin_numbers"),
                        "bin_numbers": dictionary.get("bin_numbers"),
                        "dict_template_id": dictionary.get("dict_template_id"),
                        "proximity": dictionary.get("proximity"),
                    }
                )
                module.warn("Final update payload being sent to API:")
                module.warn(str(update_data))
                updated, _unused, error = client.dlp_dictionary.update_dict(
                    **update_data
                )
                if error:
                    module.fail_json(
                        msg=f"Error updating dictionary: {to_native(error)}"
                    )
                module.exit_json(
                    changed=True, data=updated.as_dict(), drift_details=changed_fields
                )
            else:
                module.exit_json(changed=False, data=existing_dict)
        else:
            create_data = deleteNone(
                {
                    "name": dictionary.get("name"),
                    "description": dictionary.get("description"),
                    "custom_phrase_match_type": dictionary.get(
                        "custom_phrase_match_type"
                    ),
                    "dictionary_type": dictionary.get("dictionary_type"),
                    "confidence_threshold": dictionary.get("confidence_threshold"),
                    "predefined_count_action_type": dictionary.get(
                        "predefined_count_action_type"
                    ),
                    "patterns": dictionary.get("patterns"),
                    "phrases": dictionary.get("phrases"),
                    "exact_data_match_details": dictionary.get(
                        "exact_data_match_details"
                    ),
                    "idm_profile_match_accuracy": dictionary.get(
                        "idm_profile_match_accuracy"
                    ),
                    "ignore_exact_match_idm_dict": dictionary.get(
                        "ignore_exact_match_idm_dict"
                    ),
                    "include_bin_numbers": dictionary.get("include_bin_numbers"),
                    "bin_numbers": dictionary.get("bin_numbers"),
                    "dict_template_id": dictionary.get("dict_template_id"),
                    "proximity": dictionary.get("proximity"),
                }
            )
            module.warn("Final create payload being sent to API:")
            module.warn(str(create_data))
            created, _unused, error = client.dlp_dictionary.add_dict(**create_data)
            if error:
                module.fail_json(msg=f"Error creating dictionary: {to_native(error)}")
            module.exit_json(changed=True, data=created.as_dict())

    elif state == "absent":
        if existing_dict:
            _unused, _unused, error = client.dlp_dictionary.delete_dict(
                dict_id=existing_dict["id"]
            )
            if error:
                module.fail_json(msg=f"Error deleting dictionary: {to_native(error)}")
            module.exit_json(changed=True, data=existing_dict)
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    id_spec = dict(
        type="list",
        elements="int",
        required=False,
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
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
        predefined_count_action_type=dict(
            type="str",
            required=False,
            choices=[
                "PHRASE_COUNT_TYPE_UNIQUE",
                "PHRASE_COUNT_TYPE_ALL",
            ],
        ),
        phrases=dict(
            type="list",
            elements="dict",
            options=dict(
                action=dict(
                    type="str",
                    required=True,
                    choices=["PHRASE_COUNT_TYPE_UNIQUE", "PHRASE_COUNT_TYPE_ALL"],
                ),
                phrase=dict(type="str", required=True),
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
        dictionary_type=dict(
            type="str",
            required=False,
            choices=[
                "PATTERNS_AND_PHRASES",
                "EXACT_DATA_MATCH",
                "INDEXED_DATA_MATCH",
            ],
        ),
        patterns=dict(
            type="list",
            elements="dict",
            options=dict(
                action=dict(
                    type="str",
                    required=True,
                    choices=["PATTERN_COUNT_TYPE_ALL", "PATTERN_COUNT_TYPE_UNIQUE"],
                ),
                pattern=dict(type="str", required=True),
            ),
            required=False,
        ),
        exact_data_match_details=dict(
            type="list",
            elements="dict",
            options=dict(
                dictionary_edm_mapping_id=dict(type="int", required=False),
                schema_id=dict(type="int", required=False),
                primary_field=dict(type="int", required=False),
                secondary_fields=dict(type="list", elements="int", required=False),
                secondary_field_match_on=dict(
                    type="list",
                    elements="str",
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
        ignore_exact_match_idm_dict=dict(type="bool", required=False),
        include_bin_numbers=dict(type="bool", required=False),
        bin_numbers=dict(type="list", elements="str", required=False),
        dict_template_id=dict(type="int", required=False),
        proximity=dict(type="int", required=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
