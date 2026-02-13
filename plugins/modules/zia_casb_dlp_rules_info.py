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
module: zia_casb_dlp_rules_info
short_description: "Gets information about CASB DLP rules"
description:
  - "Gets a list of CASB DLP rules or retrieves a specific rule by ID or name."
  - "The rule C(type) must be specified to identify which rule category to query."
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
  type:
    description:
      - The type of SaaS Security Data at Rest Scanning DLP rule.
      - This parameter is required to identify which rule category to query.
    required: true
    type: str
    choices:
      - OFLCASB_DLP_FILE
      - OFLCASB_DLP_EMAIL
      - OFLCASB_DLP_CRM
      - OFLCASB_DLP_ITSM
      - OFLCASB_DLP_COLLAB
      - OFLCASB_DLP_REPO
      - OFLCASB_DLP_STORAGE
      - OFLCASB_DLP_GENAI
  id:
    description:
      - The unique identifier for the CASB DLP rule.
      - System-generated identifier for the SaaS Security Data at Rest Scanning DLP rule.
    required: false
    type: int
  name:
    description:
      - Rule name. Used to look up a rule by name within the specified type.
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all CASB DLP rules of type ITSM
  zscaler.ziacloud.zia_casb_dlp_rules_info:
    provider: '{{ provider }}'
    type: OFLCASB_DLP_ITSM

- name: Get a CASB DLP rule by ID
  zscaler.ziacloud.zia_casb_dlp_rules_info:
    provider: '{{ provider }}'
    type: OFLCASB_DLP_ITSM
    id: 1070199

- name: Get a CASB DLP rule by name
  zscaler.ziacloud.zia_casb_dlp_rules_info:
    provider: '{{ provider }}'
    type: OFLCASB_DLP_ITSM
    name: "My DLP Rule"
"""

RETURN = r"""
rules:
  description: A list of CASB DLP rules fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the CASB DLP rule.
      returned: always
      type: int
    name:
      description: Rule name.
      returned: always
      type: str
    type:
      description: The type of SaaS Security Data at Rest Scanning DLP rule.
      returned: always
      type: str
    description:
      description: An admin editable text-based description of the rule.
      returned: when available
      type: str
    order:
      description: Order of rule execution with respect to other rules.
      returned: always
      type: int
    rank:
      description: Admin rank assigned to the rule.
      returned: when available
      type: int
    state:
      description: Administrative state of the rule (ENABLED, DISABLED).
      returned: always
      type: str
    action:
      description: The configured action for the policy rule.
      returned: when available
      type: str
    severity:
      description: The severity level of the incidents that match the policy rule.
      returned: when available
      type: str
    bucket_owner:
      description: User who inspects their buckets for sensitive data.
      returned: when available
      type: str
    external_auditor_email:
      description: Email address of the external auditor for DLP alerts.
      returned: when available
      type: str
    content_location:
      description: The location for the content that the service inspects.
      returned: when available
      type: str
    components:
      description: List of components for which the rule is applied.
      returned: when available
      type: list
      elements: str
    collaboration_scope:
      description: Collaboration scope for the rule.
      returned: when available
      type: list
      elements: str
    file_types:
      description: File types for which the rule is applied.
      returned: when available
      type: list
      elements: str
    domains:
      description: The domain for the external organization sharing the channel.
      returned: when available
      type: list
      elements: str
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    rule_type = module.params.get("type")
    rule_id = module.params.get("id")
    rule_name = module.params.get("name")

    client = ZIAClientHelper(module)
    rules = []

    if rule_id is not None:
        rule_obj, _unused, error = client.casb_dlp_rules.get_rule(rule_id, rule_type)
        if error or rule_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve CASB DLP rule with ID '{rule_id}' (type '{rule_type}'): {to_native(error)}"
            )
        rules = [rule_obj.as_dict()]
    else:
        result, _unused, error = client.casb_dlp_rules.list_rules(
            query_params={"rule_type": rule_type}
        )
        if error:
            module.fail_json(
                msg=f"Error retrieving CASB DLP rules: {to_native(error)}"
            )

        rule_list = [r.as_dict() for r in result] if result else []

        if rule_name:
            matched = next(
                (r for r in rule_list if r.get("name") == rule_name),
                None,
            )
            if not matched:
                available = [r.get("name") for r in rule_list]
                module.fail_json(
                    msg=f"CASB DLP rule with name '{rule_name}' (type '{rule_type}') not found. Available rules: {available}"
                )
            rules = [matched]
        else:
            rules = rule_list

    module.exit_json(changed=False, rules=rules)


def main():
    rule_type_choices = [
        "OFLCASB_DLP_FILE",
        "OFLCASB_DLP_EMAIL",
        "OFLCASB_DLP_CRM",
        "OFLCASB_DLP_ITSM",
        "OFLCASB_DLP_COLLAB",
        "OFLCASB_DLP_REPO",
        "OFLCASB_DLP_STORAGE",
        "OFLCASB_DLP_GENAI",
    ]

    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        type=dict(type="str", required=True, choices=rule_type_choices),
        id=dict(type="int", required=False),
        name=dict(type="str", required=False),
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
