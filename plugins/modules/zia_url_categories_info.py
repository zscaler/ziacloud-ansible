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
module: zia_url_categories_info
short_description: "Gets information about all or custom URL categories."
description: "Gets information about all or custom URL categories."
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
    description: URL category ID. See U(https://help.zscaler.com/zia/url-categories#/urlCategories-get)
    required: false
    type: str
  name:
    description: "Name of the URL category. This is only required for custom URL categories."
    required: false
    type: str
  custom_only:
    description: If set to true, gets information on custom URL categories only.
    required: false
    type: bool
  include_only_url_keyword_counts:
    description:
      - By default this parameter is set to false, so the response includes URLs and keywords for custom URL categories only
      - If set to true, the response only includes URL and keyword counts.
    required: false
    type: bool
"""

EXAMPLES = r"""
- name: Gather Information Details of all URL Categories
  zscaler.ziacloud.zia_url_categories_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a specific URL Category by ID
  zscaler.ziacloud.zia_url_categories_info:
    provider: '{{ provider }}'
    id: "OTHER_ADULT_MATERIAL"
"""

RETURN = r"""
categories:
  description: A list of URL categories fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the URL category.
      returned: always
      type: str
      sample: "CUSTOM_02"
    name:
      description: The name configured for the URL category.
      returned: when custom categories are queried
      type: str
      sample: "Example100"
    description:
      description: The description of the URL category.
      returned: always
      type: str
      sample: "Example100"
    type:
      description: The type of the URL category.
      returned: always
      type: str
      sample: "URL_CATEGORY"
    custom_category:
      description: Indicates if the category is a custom category.
      returned: always
      type: bool
      sample: true
    editable:
      description: Indicates if the category is editable.
      returned: always
      type: bool
      sample: true
    custom_urls_count:
      description: The count of custom URLs in the category.
      returned: when custom categories are queried
      type: int
      sample: 11
    urls:
      description: A list of URLs categorized under this category.
      returned: when custom categories are queried
      type: list
      sample: [".coupons.com", ".resource.alaskaair.net"]
    custom_ip_ranges_count:
      description: The count of custom IP ranges in the category.
      returned: when custom categories are queried
      type: int
      sample: 2
    ip_ranges:
      description: A list of IP ranges categorized under this category.
      returned: when custom categories are queried
      type: list
      sample: ["3.235.112.0/24", "3.217.228.0/25"]
    ip_ranges_retaining_parent_category:
      description: List of IP ranges retaining their parent category's classification.
      returned: when custom categories are queried
      type: list
      sample: ["13.107.6.152/31"]
    ip_ranges_retaining_parent_category_count:
      description: The count of IP ranges retaining their parent category's classification.
      returned: when custom categories are queried
      type: int
      sample: 1
    keywords:
      description: Keywords associated with the category.
      returned: when custom categories are queried
      type: list
      sample: ["microsoft"]
    keywords_retaining_parent_category:
      description: Keywords retaining their parent category's classification.
      returned: when custom categories are queried
      type: list
      sample: []
    urls_retaining_parent_category_count:
      description: The count of URLs retaining their parent category's classification.
      returned: when custom categories are queried
      type: int
      sample: 2
    db_categorized_urls:
      description: A list of URLs categorized under this category by the database.
      returned: when custom categories are queried
      type: list
      sample: [".creditkarma.com", ".youku.com"]
    val:
      description: A custom value associated with the category.
      returned: when custom categories are queried
      type: int
      sample: 129
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    category_id = module.params.get("id")
    configured_name = module.params.get("name")  # Standard Ansible alias for search
    custom_only = module.params.get("custom_only")
    include_keyword_counts = module.params.get("include_only_url_keyword_counts")

    client = ZIAClientHelper(module)
    categories = []

    if category_id is not None:
        category_obj, _unused, error = client.url_categories.get_category(category_id)
        if error or category_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve URL category with ID '{category_id}': {to_native(error)}"
            )
        categories = [category_obj.as_dict()]
    else:
        query_params = {}

        # Map Ansible 'name' to search on configured_name
        if configured_name:
            query_params["search"] = configured_name
        if custom_only is not None:
            query_params["custom_only"] = custom_only
        if include_keyword_counts is not None:
            query_params["include_only_url_keyword_counts"] = include_keyword_counts

        result, _unused, error = client.url_categories.list_categories(
            query_params=query_params
        )
        if error:
            module.fail_json(msg=f"Error retrieving URL categories: {to_native(error)}")

        categories = [c.as_dict() for c in result] if result else []

    module.exit_json(changed=False, categories=categories)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="str", required=False),
        name=dict(type="str", required=False),
        custom_only=dict(type="bool", required=False),
        include_only_url_keyword_counts=dict(type="bool", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["id", "name"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
