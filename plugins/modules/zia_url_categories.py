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
module: zia_url_categories
short_description: "Adds a new custom URL category."
description:
  - "Adds a new custom URL category."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
    - zscaler.ziacloud.fragments.credentials_set
    - zscaler.ziacloud.fragments.provider
    - zscaler.ziacloud.fragments.enabled_state
"""

EXAMPLES = """
- name: Gather Information Details of a ZIA User Role
  zscaler.ziacloud.zia_url_categories:

- name: Gather Information Details of a ZIA Admin User by Name
  zscaler.ziacloud.zia_url_categories:
    name: "IOS"
"""

RETURN = """
# Returns information on a specified ZIA Admin User.
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


def normalize_url_category(category):
    """
    Normalize url category by setting computed values.
    """
    normalized = category.copy()

    computed_values = [
        "super_category",
    ]
    for attr in computed_values:
        normalized.pop(attr, None)

    return normalized


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    category = dict()
    params = [
        "id",
        "configured_name",
        "description",
        "super_category",
        "custom_category",
        "keywords",
        "keywords_retaining_parent_category",
        "urls",
        "db_categorized_urls",
        # "ip_ranges",
        # "ip_ranges_retaining_parent_category",
        "scopes",
        "editable",
        "type",
        # "custom_urls_count",
        # "urls_retaining_parent_category_count",
        # "custom_ip_ranges_count",
        # "ip_ranges_retaining_parent_category_count",
    ]
    for param_name in params:
        category[param_name] = module.params.get(param_name, None)

    category_id = category.get("id", None)
    existing_category = None
    if category_id is not None:
        categoryBox = client.url_categories.get_category(category_id=category_id)
        if categoryBox is not None:
            existing_category = categoryBox.to_dict()
    elif category.get("configured_name"):
        categories = client.url_categories.list_categories().to_list()
        for category_ in categories:
            if category_.get("configured_name") == category.get("configured_name"):
                existing_category = category_

    # Normalize and compare existing and desired data
    desired_category = normalize_url_category(category)
    current_category = (
        normalize_url_category(existing_category) if existing_category else {}
    )

    def preprocess_category(category, params):
        """
        Preprocess specific attributes in the category based on their type and structure.
        :param category: Dict containing the category data.
        :param params: List of attribute names to be processed.
        :return: Preprocessed category.
        """
        preprocessed = {}
        for attr in params:
            if attr in category:
                value = category[attr]

                # Handling the 'editable' attribute, default to False if not provided
                if attr == "editable":
                    preprocessed[attr] = False if value is None else value

                # 'super_category' is required, so it should be directly assigned
                elif attr == "super_category":
                    preprocessed[attr] = value

                # Handle list attributes
                elif isinstance(value, list):
                    preprocessed[attr] = sorted(value) if value else []

                else:
                    preprocessed[attr] = value

            else:
                # Assign default values for missing keys
                if attr == "editable":
                    preprocessed[attr] = False
                elif attr == "super_category":
                    # Assuming 'super_category' must be provided by the user
                    preprocessed[attr] = category.get(attr, "")
                else:
                    preprocessed[attr] = None

        return preprocessed

    existing_category_preprocessed = preprocess_category(current_category, params)
    desired_category_preprocessed = preprocess_category(desired_category, params)

    # Comparison logic
    differences_detected = False
    for key in params:
        desired_value = desired_category_preprocessed.get(key)
        current_value = existing_category_preprocessed.get(key)

        # Handling for list attributes where None should be treated as an empty list
        if isinstance(current_value, list) and desired_value is None:
            desired_value = []

        # Skip comparison for 'id' if it's not in the desired category but present in the existing category
        if key == "id" and desired_value is None and current_value is not None:
            continue

        if isinstance(desired_value, list) and isinstance(current_value, list):
            if all(isinstance(x, int) for x in desired_value) and all(
                isinstance(x, int) for x in current_value
            ):
                desired_value = sorted(desired_value)
                current_value = sorted(current_value)

        if current_value != desired_value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
            )

    if existing_category is not None:
        id = existing_category.get("id")
        existing_category.update(category)
        existing_category["id"] = id

    module.warn(f"Final payload being sent to SDK: {category}")
    if state == "present":
        if existing_category is not None:
            if differences_detected:
                updated_category = deleteNone(category)
                updated_category["category_id"] = existing_category.get("id")
                updated_category = client.url_categories.update_url_category(
                    **updated_category
                ).to_dict()
                module.exit_json(changed=True, data=updated_category)
            else:
                # Existing category found but no differences detected, so no changes are made
                module.exit_json(
                    changed=False,
                    data=existing_category,
                    msg="No changes needed as the existing category matches the desired state.",
                )
        else:
            created_category = deleteNone(category)
            module.warn("Payload for SDK: {}".format(created_category))
            new_category = client.url_categories.add_url_category(
                **created_category
            ).to_dict()
            module.exit_json(changed=True, data=new_category)
    elif state == "absent":
        if existing_category:
            client.url_categories.delete_category(
                category_id=existing_category.get("id")
            )
            module.exit_json(changed=True, data=existing_category)
        else:
            module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="str"),
        configured_name=dict(type="str", required=False),
        description=dict(type="str", required=False),
        custom_category=dict(type="bool", required=False),
        keywords=dict(type="list", elements="str", required=False),
        keywords_retaining_parent_category=dict(
            type="list", elements="str", required=False
        ),
        urls=dict(type="list", elements="str", required=False),
        db_categorized_urls=dict(type="list", elements="str", required=False),
        # ip_ranges=dict(type="list", elements="str", required=False),
        # ip_ranges_retaining_parent_category=dict(
        #     type="list", elements="str", required=False
        # ),
        editable=dict(type="bool", required=False),
        # custom_urls_count=dict(type="int", required=False),
        # urls_retaining_parent_category_count=dict(type="int", required=False),
        # custom_ip_ranges_count=dict(type="int", required=False),
        # ip_ranges_retaining_parent_category_count=dict(type="int", required=False),
        type=dict(
            type="str",
            required=False,
            choices=["ALL", "URL_CATEGORY", "TLD_CATEGORY"],
        ),
        scopes=dict(
            type="list",
            elements="dict",
            options=dict(
                scope_entities=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        id=dict(type="int", required=False),
                    ),
                    required=False,
                ),
                type=dict(
                    type="str",
                    required=False,
                    choices=[
                        "ORGANIZATION",
                        "DEPARTMENT",
                        "LOCATION",
                        "LOCATION_GROUP",
                    ],
                ),
            ),
            required=False,
        ),
        super_category=dict(
            type="str",
            required=False,
            choices=[
                "ANY",
                "ADVANCED_SECURITY",
                "ENTERTAINMENT_AND_RECREATION",
                "NEWS_AND_MEDIA",
                "USER_DEFINED",
                "EDUCATION",
                "BUSINESS_AND_ECONOMY",
                "JOB_SEARCH",
                "INFORMATION_TECHNOLOGY",
                "INTERNET_COMMUNICATION",
                "OFFICE_365",
                "CUSTOM_SUPERCATEGORY",
                "CUSTOM_BP",
                "CUSTOM_BW",
                "MISCELLANEOUS",
                "TRAVEL",
                "VEHICLES",
                "GOVERNMENT_AND_POLITICS",
                "GLOBAL_INT",
                "GLOBAL_INT_BP",
                "GLOBAL_INT_BW",
                "GLOBAL_INT_OFC365",
                "ADULT_MATERIAL",
                "DRUGS",
                "GAMBLING",
                "VIOLENCE",
                "WEAPONS_AND_BOMBS",
                "TASTELESS",
                "MILITANCY_HATE_AND_EXTREMISM",
                "ILLEGAL_OR_QUESTIONABLE",
                "SOCIETY_AND_LIFESTYLE",
                "HEALTH",
                "SPORTS",
                "SPECIAL_INTERESTS_SOCIAL_ORGANIZATIONS",
                "GAMES",
                "SHOPPING_AND_AUCTIONS",
                "SOCIAL_AND_FAMILY_ISSUES",
                "RELIGION",
                "SECURITY",
            ],
        ),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
