#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, Zscaler Technology Alliances <zscaler-partner-labs@z-bd.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

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
extends_documentation_fragment:
    - zscaler.ziacloud.fragments.credentials_set
    - zscaler.ziacloud.fragments.provider
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
  match_type:
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
      - Only a limited set of identification-based predefined dictionaries (e.g., Credit Cards, Social Security Numbers, National Identification Numbers, etc.) can be cloned.
      - Up to 4 clones can be created from a predefined dictionary.
    required: false
    type: int
  proximity:
    description:
      - The DLP dictionary proximity length.
    required: false
    type: int
"""

EXAMPLES = """

- name: Create/Update/Delete dlp dictionary.
  zscaler.ziacloud.zia_dlp_dictionaries:
    name: "Ansible_Test"
    description: "Ansible_Test"
    match_type: "all"
    custom_phrase_match_type: "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
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
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)

# Helper function to transform match_type
def transform_match_type(match_type):
    if match_type == "all":
        return "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
    return "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"


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
        "match_type",
        "patterns",
        "phrases",
        "exact_data_match_details",
        "idm_profile_match_accuracy",
        "ignore_exact_match_idm_dict",
        "hierarchical_identifiers"
        "include_bin_numbers",
        "bin_numbers",
        "dict_template_id",
        "proximity",
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
    if dictionary.get("match_type"):
        dictionary["custom_phrase_match_type"] = transform_match_type(dictionary.pop("match_type"))
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
                    predefined_count_action_type=existing_dictionary.get(
                        "predefined_count_action_type", ""
                    ),
                    custom_phrase_match_type=existing_dictionary.get(
                        "custom_phrase_match_type", ""
                    ),
                    match_type=existing_dictionary.get(
                        "match_type", ""
                    ),
                    phrases=existing_dictionary.get("phrases", ""),
                    patterns=existing_dictionary.get("patterns", ""),
                    exact_data_match_details=existing_dictionary.get(
                        "exact_data_match_details", ""
                    ),
                    idm_profile_match_accuracy=existing_dictionary.get(
                        "idm_profile_match_accuracy", ""
                    ),
                    ignore_exact_match_idm_dict=existing_dictionary.get(
                        "ignore_exact_match_idm_dict", ""
                    ),
                    hierarchical_identifiers=existing_dictionary.get(
                        "hierarchical_identifiers", ""
                    ),
                    include_bin_numbers=existing_dictionary.get(
                        "include_bin_numbers", ""
                    ),
                    bin_numbers=existing_dictionary.get(
                        "bin_numbers", ""
                    ),
                    dict_template_id=existing_dictionary.get(
                        "dict_template_id", ""
                    ),
                    proximity=existing_dictionary.get("proximity", ""),
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
                    patterns=dictionary.get("patterns", ""),
                    custom_phrase_match_type=dictionary.get(
                        "custom_phrase_match_type", ""
                    ),
                    match_type=dictionary.get(
                        "match_type", ""
                    ),
                    exact_data_match_details=dictionary.get(
                        "exact_data_match_details", ""
                    ),
                    idm_profile_match_accuracy=dictionary.get(
                        "idm_profile_match_accuracy", ""
                    ),
                    ignore_exact_match_idm_dict=dictionary.get(
                        "ignore_exact_match_idm_dict", ""
                    ),
                    hierarchical_identifiers=dictionary.get(
                        "hierarchical_identifiers", ""
                    ),
                    include_bin_numbers=dictionary.get(
                        "include_bin_numbers", ""
                    ),
                    bin_numbers=dictionary.get(
                        "bin_numbers", ""
                    ),
                    dict_template_id=dictionary.get(
                        "dict_template_id", ""
                    ),
                    proximity=dictionary.get("proximity", ""),
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
        match_type=dict(
            type="str",
            required=False,
            choices=[
                "all",
                "any"
                # "EXACT_DATA_MATCH",
                # "INDEXED_DATA_MATCH",
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
