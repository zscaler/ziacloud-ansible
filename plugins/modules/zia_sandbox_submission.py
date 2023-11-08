#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Technology Alliances, <zscaler-partner-labs@z-bd.com>

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_sandbox_submit
short_description: "Submits a file to the ZIA Advanced Cloud Sandbox for analysis."
description:
  - Submits a file to the ZIA Advanced Cloud Sandbox for analysis.
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
options:
  username:
    description: "Username of admin user that is provisioned"
    required: true
    type: str
  password:
    description: "Password of the admin user"
    required: true
    type: str
  api_key:
    description: "The obfuscated form of the API key"
    required: true
    type: str
  base_url:
    description: "The host and basePath for the cloud services API"
    required: true
    type: str
  file_path:
    description: "Path to the file that will be submitted for sandbox analysis."
    type: str
    required: true
  force:
    description: "Force ZIA to analyse the file even if it has been submitted previously."
    type: bool
    default: False
"""

EXAMPLES = """
- name: Submit a file for analysis.
  zscaler.ziacloud.zia_sandbox_submit:
    file_path: "/path/to/malware.exe"
    force: True
"""

RETURN = """
# The Cloud Sandbox submission response information.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    zia_argument_spec,
)
from zscaler import ZIA


def core(module):
    file_path = module.params.get("file_path", "")
    force = module.params.get("force", False)
    inspection_mode = module.params.get(
        "inspection_mode", "sandbox"
    )  # either 'sandbox' or 'out_of_band'

    client = ZIA(
        api_key=module.params.get("api_key", ""),
        cloud=module.params.get("base_url", ""),
        username=module.params.get("username", ""),
        password=module.params.get("password", ""),
    )

    sandbox_api = client.sandbox

    if inspection_mode == "sandbox":
        result = sandbox_api.submit_file(file_path, force=force)
    elif inspection_mode == "out_of_band":
        result = sandbox_api.submit_file_for_inspection(file_path)

    if result:
        module.exit_json(changed=True, submission_response=result)
    else:
        module.exit_json(changed=False, msg="Submission failed.")


def main():
    argument_spec = zia_argument_spec()
    argument_spec.update(
        file_path=dict(type="str", required=True),
        force=dict(type="bool", default=False),
        inspection_mode=dict(
            type="str", choices=["sandbox", "out_of_band"], default="sandbox"
        ),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
