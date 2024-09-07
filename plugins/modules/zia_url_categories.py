# #!/usr/bin/python
# # -*- coding: utf-8 -*-
# #
# # Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

# #                             MIT License
# # Permission is hereby granted, free of charge, to any person obtaining a copy
# # of this software and associated documentation files (the "Software"), to deal
# # in the Software without restriction, including without limitation the rights
# # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# # copies of the Software, and to permit persons to whom the Software is
# # furnished to do so, subject to the following conditions:

# # The above copyright notice and this permission notice shall be included in all
# # copies or substantial portions of the Software.

# # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# # SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
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
notes:
    - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  id:
    description: URL category ID. See U(https://help.zscaler.com/zia/url-categories#/urlCategories-get)
    required: false
    type: str
  configured_name:
    description: "Name of the URL category. This is only required for custom URL categories."
    required: false
    type: str
  description:
    description: "Description of the URL category."
    required: false
    type: str
  super_category:
    description:
        - Super Category of the URL category.
        - This field is required when creating custom URL categories.
    required: false
    type: str
  editable:
    description: Value is set to false for custom URL category when due to scope user does not have edit permission
    required: false
    type: bool
  type:
    description: "Type of the custom categories."
    required: false
    type: str
    choices:
        - URL_CATEGORY
        - TLD_CATEGORY
        - ALL
  keywords:
    description:
        - Custom keywords associated to a URL category.
        - "Up to 2048 custom keywords can be added per organization across all categories including bandwidth classes"
    required: false
    type: list
    elements: str
  keywords_retaining_parent_category:
    description:
        - "Retained custom keywords from the parent URL category that is associated to a URL category."
        - "Up to 2048 retained parent keywords can be added per organization across all categories including bandwidth classes."
    required: false
    type: list
    elements: str
  urls:
    description:
        - Retained custom keywords from the parent URL category that is associated to a URL category.
        - "Up to 2048 retained parent keywords can be added per organization across all categories including bandwidth classes."
    required: false
    type: list
    elements: str
  db_categorized_urls:
    description:
        - URLs added to a custom URL category are also retained under the original parent URL category.
        - i.e. the predefined category the URL previously belonged to.
        - The URLs entered are covered by policies that reference the original parent URL category.
        - If you add www.amazon.com, this URL is covered by policies that reference the custom URL category.
    required: false
    type: list
    elements: str
  ip_ranges:
    description:
        - Custom IP address ranges associated to a URL category.
        - Up to 2000 custom IP address ranges and retaining parent custom IP address ranges can be added, per organization, across all categories.
        - This field is available only if the option to configure custom IP ranges is enabled for your organization.
        - To enable this option, contact Zscaler Support.
    required: false
    type: list
    elements: str
  ip_ranges_retaining_parent_category:
    description:
        - The retaining parent custom IP address ranges associated to a URL category.
        - Up to 2000 custom IP ranges and retaining parent custom IP address ranges can be added, per organization, across all categories.
    required: false
    type: list
    elements: str
  custom_category:
    description:
        - Set to true for custom URL category. Up to 48 custom URL categories can be added per organization.
    required: false
    type: bool
  scopes:
    description:
      - Scope of the custom categories.
    type: list
    elements: dict
    required: false
    suboptions:
        type:
            type: str
            required: false
            description:
                - The admin scope type. The attribute name is subject to change.
            choices:
                - ORGANIZATION
                - DEPARTMENT
                - LOCATION
                - LOCATION_GROUP
        scope_entities:
            description:
                - Based on the admin scope type, the entities can be the ID/name pair of departments, locations, or location groups.
                - The attribute name is subject to change.
            type: list
            elements: int
            required: false
"""

EXAMPLES = r"""
- name: Create a URL Category
  zscaler.ziacloud.zia_url_categories:
    provider: '{{ provider }}'
    super_category: USER_DEFINED
    configured_name: Example_Category
    description: Example_Category
    type: URL_CATEGORY
    keywords:
      - microsoft
    custom_category: true
    db_categorized_urls:
      - .creditkarma.com
      - .youku.com
    urls:
      - .coupons.com
      - .resource.alaskaair.net
      - .techrepublic.com
      - .dailymotion.com
      - .osiriscomm.com
      - .uefa.com
      - .Logz.io
      - .alexa.com
      - .baidu.com
      - .cnn.com
      - .level3.com
"""

RETURN = r"""
# Returns information on a specified custom URL Categories.
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
    Normalize URL category data by setting computed values and sorting URLs.
    """
    normalized = category.copy()

    computed_values = ["id"]
    for attr in computed_values:
        normalized.pop(attr, None)

    # Sort URLs for consistent comparison
    if "urls" in normalized and normalized["urls"] is not None:
        normalized["urls"] = sorted(normalized["urls"])

    return normalized


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
                preprocessed[attr] = True if value is None else value

            # Handle list attributes
            elif isinstance(value, list):
                preprocessed[attr] = sorted(value) if value else []

            else:
                preprocessed[attr] = value

        else:
            # Assign default values for missing keys
            if attr == "editable":
                preprocessed[attr] = False
            else:
                preprocessed[attr] = None

    return preprocessed


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    category = dict()
    params = [
        "id",
        "configured_name",
        "description",
        "super_category",  # This will be excluded from the comparison
        "custom_category",
        "keywords",
        "keywords_retaining_parent_category",
        "urls",
        "db_categorized_urls",
        "ip_ranges",
        "ip_ranges_retaining_parent_category",
        "scopes",
        "type",
        "editable",
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

    existing_category_preprocessed = preprocess_category(current_category, params)
    desired_category_preprocessed = preprocess_category(desired_category, params)

    # Exclude 'super_category' from the comparison
    if "super_category" in desired_category_preprocessed:
        desired_category_preprocessed.pop("super_category")
    if "super_category" in existing_category_preprocessed:
        existing_category_preprocessed.pop("super_category")

    # Comparison logic
    differences_detected = False
    for key in params:
        if key == "super_category":
            continue
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
            # module.warn(
            #     f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
            # )

    if module.check_mode:
        # If in check mode, report changes and exit
        if state == "present" and (existing_category is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_category is not None:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if existing_category is not None:
        id = existing_category.get("id")
        existing_category.update(category)
        existing_category["id"] = id

    # module.warn(f"Final payload being sent to SDK: {category}")
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
            # module.warn("Payload for SDK: {}".format(created_category))
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
    id_spec = dict(
        type="list",
        elements="int",
        required=False,
    )
    argument_spec.update(
        id=dict(type="str"),
        configured_name=dict(type="str", required=False),
        description=dict(type="str", required=False),
        custom_category=dict(type="bool", required=False),
        keywords=dict(type="list", elements="str", required=False, no_log=True),
        keywords_retaining_parent_category=dict(
            type="list", elements="str", required=False, no_log=True
        ),
        urls=dict(type="list", elements="str", required=False),
        db_categorized_urls=dict(type="list", elements="str", required=False),
        ip_ranges=dict(type="list", elements="str", required=False),
        ip_ranges_retaining_parent_category=dict(
            type="list", elements="str", required=False
        ),
        editable=dict(type="bool", required=False),
        type=dict(
            type="str",
            required=False,
            choices=["ALL", "URL_CATEGORY", "TLD_CATEGORY"],
        ),
        scopes=dict(
            type="list",
            elements="dict",
            options=dict(
                scope_entities=id_spec,
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
