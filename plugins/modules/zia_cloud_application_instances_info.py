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
module: zia_cloud_application_instances_info
short_description: "Retrieves the list of cloud application instances"
description:
  - "Retrieves the list of cloud application instances"
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

options:
  instance_id:
    description: "Cloud application instance ID"
    type: int
    required: false
  instance_name:
    description: "The cloud application instance name"
    required: false
    type: str
  instance_type:
    description: "The cloud application instance type"
    required: false
    type: str
    choices:
        - SHAREPOINTONLINE
        - ONEDRIVE
        - BOXNET
        - OKTA
        - APPSPACE
        - BITBUCKET
        - GITHUB
        - SLACK
        - QUICK_BASE
        - ZEPLIN
        - SOURCEFORGE
        - ZOOM
        - WORKDAY
        - GDRIVE
        - GOOGLE_WEBMAIL
        - WINDOWS_LIVE_HOTMAIL
        - MSTEAM
"""

EXAMPLES = r"""
- name: Gets all list of cloud application instances
  zscaler.ziacloud.zia_cloud_application_instances_info:
    provider: '{{ provider }}'
    instance_id: 124547686

- name: Gets a list of cloud application instances by instance name
  zscaler.ziacloud.zia_cloud_application_instances_info:
    provider: '{{ provider }}'
    instance_name: "example"

- name: Gets a list of cloud application instances by instance type
  zscaler.ziacloud.zia_cloud_application_instances_info:
    provider: '{{ provider }}'
    instance_type: "example"
"""

RETURN = r"""
instances:
  description: A list of cloud application instances retrieved based on the filter criteria.
  returned: always
  type: list
  elements: dict
  contains:
    instance_id:
      description: The unique identifier of the cloud application instance.
      type: int
      returned: always
      sample: 1324545
    instance_name:
      description: The name of the cloud application instance.
      type: str
      returned: always
      sample: "Instance01_Ansible"
    instance_type:
      description: The type of cloud application instance.
      type: str
      returned: always
      sample: "SHAREPOINTONLINE"
    modified_at:
      description: The timestamp when the instance was last modified (epoch).
      type: int
      returned: always
      sample: 1746507565
    modified_by:
      description: Information about the user who last modified the instance.
      type: dict
      returned: always
      contains:
        id:
          description: ID of the modifying user.
          type: int
          sample: 19475409
        name:
          description: Name of the modifying user.
          type: str
          sample: "oauth-user@company.net"
        external_id:
          description: Whether this user has an external identity.
          type: bool
          sample: false
        extensions:
          description: Additional metadata about the user.
          type: dict
    instance_identifiers:
      description: A list of identifiers that define the instance.
      type: list
      elements: dict
      returned: always
      contains:
        instance_identifier:
          description: The URL, keyword, or IP address that identifies the instance.
          type: str
          sample: "sharepoint01.sharepoint.com"
        instance_identifier_name:
          description: The friendly name of the identifier.
          type: str
          sample: "sharepoint01"
        identifier_type:
          description: The type of the identifier.
          type: str
          sample: "URL"
        instance_id:
          description: The instance ID associated with the identifier.
          type: int
          sample: 1324545
        modified_at:
          description: The timestamp when the identifier was last modified (epoch).
          type: int
        modified_by:
          description: Information about the user who last modified the identifier.
          type: dict
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    instance_id = module.params.get("instance_id")
    instance_name = module.params.get("instance_name")
    instance_type = module.params.get("instance_type")

    client = ZIAClientHelper(module)
    instances = []

    if instance_id is not None:
        instance_obj, _unused, error = (
            client.cloud_app_instances.get_cloud_app_instances(instance_id)
        )
        if error or instance_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve cloud application instance with ID '{instance_id}': {to_native(error)}"
            )
        instances = [instance_obj.as_dict()]
    else:
        query_params = {}
        if instance_name:
            query_params["instanceName"] = instance_name
        if instance_type:
            query_params["instanceType"] = instance_type

        result, _unused, error = client.cloud_app_instances.list_cloud_app_instances(
            query_params=query_params
        )
        if error:
            module.fail_json(
                msg=f"Error retrieving cloud application instances: {to_native(error)}"
            )

        instances = [r.as_dict() for r in result] if result else []

    module.exit_json(changed=False, instances=instances)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            instance_id=dict(type="int", required=False),
            instance_name=dict(type="str", required=False),
            instance_type=dict(
                type="str",
                required=False,
                choices=[
                    "SHAREPOINTONLINE",
                    "ONEDRIVE",
                    "BOXNET",
                    "OKTA",
                    "APPSPACE",
                    "BITBUCKET",
                    "GITHUB",
                    "SLACK",
                    "QUICK_BASE",
                    "ZEPLIN",
                    "SOURCEFORGE",
                    "ZOOM",
                    "WORKDAY",
                    "GDRIVE",
                    "GOOGLE_WEBMAIL",
                    "WINDOWS_LIVE_HOTMAIL",
                    "MSTEAM",
                ],
            ),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ["instance_id", "instance_name"],
            ["instance_id", "instance_type"],
        ],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
