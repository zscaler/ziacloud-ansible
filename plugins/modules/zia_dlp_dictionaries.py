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
module: zia_dlp_dictionaries
short_description: "Adds a new custom DLP dictionary."
description:
  - "Create a new custom DLP dictionary."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.credentials_set
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
  hierarchical_identifiers:
    description:
        - The list of identifiers selected within a DLP dictionary of hierarchical type.
        - Each identifier represents a sub-dictionary that consists of specific patterns.
    required: false
    type: str
    choices:
        - CRED_AMAZON_MWS_TOKEN, CRED_GIT_TOKEN, CRED_GITHUB_TOKEN, CRED_GOOGLE_API, CRED_GOOGLE_OAUTH_TOKEN,
        - CRED_GOOGLE_OAUTH_ID, CRED_JWT_TOKEN, CRED_PAYPAL_TOKEN, CRED_PICATIC_API_KEY, CRED_PRIVATE_KEY,
        - CRED_SENDGRID_API_KEY, CRED_SLACK_TOKEN, CRED_SLACK_WEBHOOK, CRED_SQUARE_ACCESS_TOKEN, CRED_SQUARE_OAUTH_SECRET,
        - CRED_STRIPE_API_KEY, EUPP_AT, EUPP_BE, EUPP_BG, EUPP_CZ, EUPP_DK, EUPP_EE, EUPP_FL, EUPP_FR, EUPP_DE, EUPP_GR,
        - EUPP_HU, EUPP_IE, EUPP_IT, EUPP_LV, EUPP_LU, EUPP_NL, EUPP_PL, EUPP_PT, EUPP_RO, EUPP_SK, EUPP_SI, EUPP_ES, EUPP_SE,
        - USDL_AL, USDL_AK, USDL_AZ, USDL_AR, USDL_CA, USDL_CO, USDL_CT, USDL_DE, USDL_DC, USDL_FL, USDL_GA, USDL_HI, USDL_ID,
        - USDL_IL, USDL_IN, USDL_IA, USDL_KS, USDL_KY, USDL_LA, USDL_ME, USDL_MD, USDL_MA, USDL_MI, USDL_MN, USDL_MS, USDL_MO,
        - USDL_MT, USDL_NE, USDL_NV, USDL_NH, USDL_NJ, USDL_NM, USDL_NY, USDL_NC, USDL_ND, USDL_OH, USDL_OK, USDL_OR, USDL_PA,
        - USDL_RI, USDL_SC, USDL_SD, USDL_TN, USDL_TX, USDL_UT, USDL_VT, USDL_VA, USDL_WA, USDL_WV, USDL_WI, USDL_WY
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
    provider: '{{ zia_cloud }}'
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
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_dlp_dictionary(dictionary):
    """
    Normalize dlp dictionary data by setting computed values.
    """
    normalized = dictionary.copy()

    computed_values = [
        "id",
        "exact_data_match_details",
        "ignore_exact_match_idm_dict",
        "include_bin_numbers",
        "dict_template_id",
        "proximity",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    dictionary = dict()
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
        "hierarchical_identifiers",
        "include_bin_numbers",
        "bin_numbers",
        "dict_template_id",
        "proximity",
    ]
    for param_name in params:
        dictionary[param_name] = module.params.get(param_name, None)

    dict_id = dictionary.get("id", None)
    existing_dictionary = None
    if dict_id is not None:
        dictBox = client.dlp.get_dict(dict_id=dict_id)
        if dictBox is not None:
            existing_dictionary = dictBox.to_dict()
    elif dictionary.get("name"):
        dictionaries = client.dlp.list_dicts().to_list()
        for dictionary_ in dictionaries:
            if dictionary_.get("name") == dictionary.get("name"):
                existing_dictionary = dictionary_

    # Normalize and compare existing and desired data
    desired_dictionary = normalize_dlp_dictionary(dictionary)
    current_dictionary = (
        normalize_dlp_dictionary(existing_dictionary) if existing_dictionary else {}
    )

    fields_to_exclude = ["id"]
    differences_detected = False
    for key, value in desired_dictionary.items():
        if key not in fields_to_exclude and current_dictionary.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_dictionary.get(key)}, Desired: {value}"
            )

    if existing_dictionary is not None:
        id = existing_dictionary.get("id")
        existing_dictionary.update(desired_dictionary)
        existing_dictionary["id"] = id

    if state == "present":
        if existing_dictionary is not None:
            if differences_detected:
                updated_dict = deleteNone(dictionary)
                updated_dict["dict_id"] = existing_dictionary.get("id")
                updated_dictionary = client.dlp.update_dict(**updated_dict).to_dict()
                module.exit_json(changed=True, data=updated_dictionary)
            else:
                # Existing dictionary found but no differences detected, so no changes are made
                module.exit_json(
                    changed=False,
                    data=existing_dictionary,
                    msg="No changes needed as the existing dictionary matches the desired state.",
                )
        else:
            created_dict = deleteNone(dictionary)
            new_dictionary = client.dlp.add_dict(**created_dict).to_dict()
            module.exit_json(changed=True, data=new_dictionary)
    elif state == "absent":
        if existing_dictionary:
            client.dlp.delete_dict(dict_id=existing_dictionary.get("id"))
            module.exit_json(changed=True, data=existing_dictionary)
        else:
            module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    id_spec = dict(
        type="list",
        elements="str",
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
                    choices=["PATTERN_COUNT_TYPE_ALL", "PATTERN_COUNT_TYPE_UNIQUE"],
                ),
                pattern=dict(type="str", required=False),
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
