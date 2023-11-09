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
    - zscaler.zpacloud.fragments.credentials_set
    - zscaler.zpacloud.fragments.provider
    - zscaler.zpacloud.fragments.enabled_state
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


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)
    category = dict()
    params = [
        "id",
        "configured_name",
        "keywords",
        "keywords_retaining_parent_category",
        "urls",
        "db_categorized_urls",
        "ip_ranges",
        "ip_ranges_retaining_parent_category",
        "custom_category",
        "scopes",
        "editable",
        "description",
        "type",
        "url_keyword_counts",
        "custom_urls_count",
        "urls_retaining_parent_category_count",
        "custom_ip_ranges_count",
        "ip_ranges_retaining_parent_category_count",
    ]
    for param_name in params:
        category[param_name] = module.params.get(param_name, None)
    category_id = category.get("id", None)
    category_name = category.get("name", None)
    existing_category = None
    if category_id is not None:
        categoryBox = client.url_categories.get_category(category_id=category_id)
        if categoryBox is not None:
            existing_category = categoryBox.to_dict()
    elif category_name is not None:
        rules = client.url_categories.list_categories().to_list()
        for category_ in rules:
            if category_.get("name") == category_name:
                existing_category = category_
    if existing_category is not None:
        id = existing_category.get("id")
        existing_category.update(category)
        existing_category["id"] = id
    if state == "present":
        if existing_category is not None:
            """Update"""
            existing_category = deleteNone(
                dict(
                    category_id=existing_category.get("id"),
                    name=existing_category.get("name"),
                    order=existing_category.get("order"),
                    protocols=existing_category.get("protocols"),
                    locations=existing_category.get("locations"),
                    groups=existing_category.get("groups"),
                    departments=existing_category.get("departments"),
                    users=existing_category.get("users"),
                    url_categories=existing_category.get("url_categories"),
                    state=existing_category.get("rule_state"),
                    time_windows=existing_category.get("time_windows"),
                    rank=existing_category.get("rank"),
                    request_methods=existing_category.get("request_methods"),
                    end_user_notification_url=existing_category.get(
                        "end_user_notification_url"
                    ),
                    override_users=existing_category.get("override_users"),
                    override_groups=existing_category.get("override_users"),
                    block_override=existing_category.get("block_override"),
                    time_quota=existing_category.get("time_quota"),
                    size_quota=existing_category.get("size_quota"),
                    description=existing_category.get("description"),
                    location_groups=existing_category.get("location_groups"),
                    labels=existing_category.get("labels"),
                    validity_start_time=existing_category.get("validity_start_time"),
                    validity_end_time=existing_category.get("validity_end_time"),
                    validity_time_zone_id=existing_category.get(
                        "validity_time_zone_id"
                    ),
                    last_modified_time=existing_category.get("last_modified_time"),
                    last_modified_by=existing_category.get("last_modified_by"),
                    enforce_time_validity=existing_category.get(
                        "enforce_time_validity"
                    ),
                    action=existing_category.get("action"),
                    cipa_rule=existing_category.get("cipa_rule"),
                )
            )
            existing_category = client.url_categories.update_url_category(
                **existing_category
            ).to_dict()
            module.exit_json(changed=True, data=existing_category)
        else:
            """Create"""
            category = deleteNone(
                dict(
                    name=rule.get("name"),
                    order=rule.get("order"),
                    protocols=rule.get("protocols"),
                    locations=rule.get("locations"),
                    groups=rule.get("groups"),
                    departments=rule.get("departments"),
                    users=rule.get("users"),
                    url_categories=rule.get("url_categories"),
                    state=rule.get("rule_state"),
                    time_windows=rule.get("time_windows"),
                    rank=rule.get("rank"),
                    request_methods=rule.get("request_methods"),
                    end_user_notification_url=rule.get("end_user_notification_url"),
                    override_users=rule.get("override_users"),
                    override_groups=rule.get("override_users"),
                    block_override=rule.get("block_override"),
                    time_quota=rule.get("time_quota"),
                    size_quota=rule.get("size_quota"),
                    description=rule.get("description"),
                    location_groups=rule.get("location_groups"),
                    labels=rule.get("labels"),
                    validity_start_time=rule.get("validity_start_time"),
                    validity_end_time=rule.get("validity_end_time"),
                    validity_time_zone_id=rule.get("validity_time_zone_id"),
                    last_modified_time=rule.get("last_modified_time"),
                    last_modified_by=rule.get("last_modified_by"),
                    enforce_time_validity=rule.get("enforce_time_validity"),
                    action=rule.get("action"),
                    cipa_rule=rule.get("cipa_rule"),
                )
            )
            rule = client.url_categories.add_url_category(**rule).to_dict()
            module.exit_json(changed=True, data=rule)
    elif state == "absent":
        if existing_category is not None:
            code = client.url_filters.delete_rule(
                category_id=existing_category.get("id")
            )
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_category)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int"),
        configured_name=dict(type="str", required=True),
        description=dict(type="str", required=True),
        custom_category=dict(type="bool", required=False),
        editable=dict(type="bool", required=False),
        type=dict(
            type="str",
            required=True,
            default="ALL",
            choices=["URL_CATEGORY", "TLD_CATEGORY"],
        ),
        custom_urls_count=dict(type="int", required=False),
        urls_retaining_parent_category_count=dict(type="int", required=False),
        custom_ip_ranges_count=dict(type="int", required=False),
        ip_ranges_retaining_parent_category_count=dict(type="int", required=False),
        keywords=dict(type="list", elements="str", required=False),
        keywords_retaining_parent_category=dict(
            type="list", elements="str", required=False
        ),
        urls=dict(type="list", elements="str", required=False),
        db_categorized_urls=dict(type="list", elements="str", required=False),
        ip_ranges=dict(type="list", elements="str", required=False),
        ip_ranges_retaining_parent_category=dict(
            type="list", elements="str", required=False
        ),
        scopes=dict(
            type="list",
            elements="dict",
            options=dict(
                scope_group_member_entities=dict(type="str"),
                id=dict(type="int", required=False),
                extensions=dict(type="list", elements="str", required=False),
                scope_entities=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        id=dict(type="int"),
                        extensions=dict(type="list", elements="str", required=False),
                    ),
                    required=False,
                ),
                type=dict(
                    type="str",
                    required=True,
                    default="ORGANIZATION",
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
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
