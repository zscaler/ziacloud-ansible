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
  configured_name:
    description: "Name of the URL category. This is only required for custom URL categories."
    required: false
    type: str

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
# Returns information on a specified url category.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    category_id = module.params.get("id", None)
    configured_name = module.params.get("configured_name", None)
    client = ZIAClientHelper(module)

    # Retrieve all categories
    categories = client.url_categories.list_categories().to_list()

    # Search by ID
    if category_id is not None:
        for category in categories:
            if category.get("id") == category_id:
                module.exit_json(changed=False, data=[category])
        module.fail_json(msg="Failed to retrieve URL category ID: '%s'" % (category_id))

    # Search by Configured Name for Custom Categories
    elif configured_name is not None:
        for category in categories:
            if (
                category.get("custom_category")
                and category.get("configured_name") == configured_name
            ):
                module.exit_json(changed=False, data=[category])
        module.fail_json(
            msg="Failed to retrieve URL category with configured name: '%s'"
            % (configured_name)
        )

    # If neither ID nor Configured Name is provided, return all categories
    else:
        module.exit_json(changed=False, categories=categories)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="str", required=False),
        configured_name=dict(type="str", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
