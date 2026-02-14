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
module: zia_ftp_control_policy
short_description: "Updates the FTP Control settings"
description:
  - "Updates the FTP Control settings"
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.modified_state

options:
  ftp_over_http_enabled:
    description:
      - Indicates whether to enable FTP over HTTP.
    type: bool
    required: false
  ftp_enabled:
    description: Indicates whether to enable native FTP.
    type: bool
    required: false
  url_categories:
    description:
      - List of URL categories that allow FTP traffic
      - Use the info resource zia_url_categories_info to retrieve the category names.
    required: false
    type: list
    elements: str
  urls:
    description:
        - Domains or URLs included for the FTP Control settings
    type: list
    elements: str
    required: false
"""

EXAMPLES = r"""
- name: Updates the FTP Control Policy
  zscaler.ziacloud.zia_ftp_control_policy:
    provider: '{{ provider }}'
    ftp_over_http_enabled: true
    ftp_enabled: true
    url_categories:
      - GENERAL_AI_ML
      - AI_ML_APPS
    urls:
      - test1.acme.com
      - test2.acme.com
"""

RETURN = r"""
#  FTP Control Policy Configured.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    state = module.params.get("state")
    if state != "present":
        module.fail_json(msg="Only 'present' is supported for this module.")

    client = ZIAClientHelper(module)

    params = [
        "ftp_over_http_enabled",
        "ftp_enabled",
        "url_categories",
        "urls",
    ]

    settings_data = {k: module.params[k] for k in params if module.params.get(k) is not None}

    current_settings, _unused, error = client.ftp_control_policy.get_ftp_settings()
    if error:
        module.fail_json(msg=f"Error fetching ftp control settings: {to_native(error)}")

    current_dict = current_settings.as_dict()

    # ✅ Attributes that should ignore ordering
    unordered_fields = ["urls", "url_categories"]

    drift = False
    for key in settings_data:
        desired = settings_data[key]
        current = current_dict.get(key)

        if key in unordered_fields and isinstance(desired, list) and isinstance(current, list):
            if set(desired) != set(current):
                drift = True
                break
        else:
            if desired != current:
                drift = True
                break

    module.warn(f"📦 Raw SDK response: {current_settings}")
    module.warn(f"📥 Desired settings: {settings_data}")
    module.warn(f"🧠 Drift detected: {drift}")

    if module.check_mode:
        module.exit_json(changed=drift, ftp_settings=current_dict)

    if drift:
        updated, _unused, error = client.ftp_control_policy.update_ftp_settings(**settings_data)
        if error:
            module.fail_json(msg=f"Error updating ftp control settings: {to_native(error)}")
        module.exit_json(changed=True, ftp_settings=updated.as_dict())

    module.exit_json(changed=False, ftp_settings=current_dict)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        ftp_over_http_enabled=dict(type="bool", required=False),
        ftp_enabled=dict(type="bool", required=False),
        url_categories=dict(type="list", elements="str", required=False),
        urls=dict(type="list", elements="str", required=False),
        state=dict(type="str", choices=["present"], default="present"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
