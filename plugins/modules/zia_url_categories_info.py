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
module: zia_url_categories_info
short_description: "Gets information about all or custom URL categories."
description: "Gets information about all or custom URL categories."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
"""

EXAMPLES = """
- name: Gather Information Details of all URL Categories
  zscaler.ziacloud.zia_url_categories_info:

- name: Gather Information Details of a specific URL Category by ID
  zscaler.ziacloud.zia_url_categories_info:
    id: "OTHER_ADULT_MATERIAL"
"""

RETURN = """
# Returns information on a specified url category.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    zia_argument_spec,
)
from zscaler import ZIA


def core(module: AnsibleModule):
    category_id = module.params.get("id", None)
    # category_name = module.params.get("name", None)
    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )
    categories = []
    if category_id is not None:
        categoryBox = client.url_categories.get_category(category_id=category_id)
        if categoryBox is None:
            module.fail_json(
                msg="Failed to retrieve url category ID: '%s'" % (category_id)
            )
        categories = [categoryBox.to_dict()]
    else:
        categories = client.url_categories.list_categories().to_list()
        if category_id is not None:
            categoryFound = False
            for category in categories:
                if category.get("id") == category_id:
                    categoryFound = True
                    categories = [category]
            if not categoryFound:
                module.fail_json(
                    msg="Failed to retrieve url category name: '%s'" % (category_id)
                )
    module.exit_json(changed=False, data=categories)


def main():
    argument_spec = zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="str", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
