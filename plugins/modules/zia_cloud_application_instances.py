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
module: zia_cloud_application_instances
short_description: "Add a new cloud application instance"
description:
  - "Add a new cloud application instance"
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
requirements:
  - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
  - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

options:
  instance_id:
    description: "The unique identifier for the cloud application instance."
    type: int
  instance_name:
    description: "Name of the cloud application instance."
    required: true
    type: str
  instance_type:
    description:
      - Type of the cloud application instance.
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
    required: true
    type: str
  instance_identifiers:
    description: List of cloud application instance identifiers
    required: true
    type: list
    elements: dict
    suboptions:
      instance_identifier:
        description: "The URL, IP address, or keyword for the cloud app instance."
        required: true
        type: str
      instance_identifier_name:
        description: "The name assigned to the instance identifier."
        required: true
        type: str
      identifier_type:
        description:
            - Type of identifier.
        choices:
            - URL
            - REFURL
            - KEYWORD
        required: true
        type: str
"""

EXAMPLES = r"""
- name: Configure cloud application instance
  zscaler.ziacloud.zia_cloud_application_instances:
    state: present
    instance_name: "Instance01_Ansible"
    instance_type: "SHAREPOINTONLINE"
    instance_identifiers:
      - instance_identifier_name: sharepoint01
        instance_identifier: sharepoint01.sharepoint.com
        identifier_type: URL

      - instance_identifier_name: "sharepoint02"
        instance_identifier: "sharepoint02.sharepoint.com"
        identifier_type: "URL"
"""

RETURN = r"""
# The newly created cloud application instance resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_instance(app_instance):
    """
    Normalize a cloud app instance dict for comparison by removing computed fields.
    """
    normalized = app_instance.copy() if app_instance else {}
    computed_values = ["instance_id", "modified_at", "modified_by"]

    for attr in computed_values:
        normalized.pop(attr, None)

    identifiers = normalized.get("instance_identifiers")
    if isinstance(identifiers, list):
        cleaned_identifiers = []
        for item in identifiers:
            item = item.copy()
            for computed_key in ["instance_id", "modified_by", "modified_at"]:
                item.pop(computed_key, None)
            cleaned_identifiers.append(item)
        normalized["instance_identifiers"] = sorted(
            cleaned_identifiers, key=lambda x: x["instance_identifier_name"]
        )

    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    instance_params = {
        p: module.params.get(p)
        for p in [
            "instance_id",
            "instance_name",
            "instance_type",
            "instance_identifiers",
        ]
    }
    instance_id = instance_params.get("instance_id")
    instance_name = instance_params.get("instance_name")

    existing_instance = None

    if instance_id:
        result, _unused, error = client.cloud_app_instances.get_cloud_app_instances(
            instance_id
        )
        if error:
            module.fail_json(
                msg=f"Error fetching cloud application instance with id {instance_id}: {to_native(error)}"
            )
        existing_instance = result.as_dict()
    else:
        result, _unused, error = client.cloud_app_instances.list_cloud_app_instances()
        if error:
            module.fail_json(
                msg=f"Error listing cloud application instances: {to_native(error)}"
            )
        instances_list = [instance.as_dict() for instance in result]
        if instance_name:
            for instance in instances_list:
                if instance.get("instance_name") == instance_name:
                    existing_instance = instance
                    break

    normalized_desired = normalize_instance(instance_params)
    normalized_existing = (
        normalize_instance(existing_instance) if existing_instance else {}
    )

    differences_detected = False
    for key, value in normalized_desired.items():
        if normalized_existing.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing.get(key)}, Desired: {value}"
            )

    if module.check_mode:
        if state == "present" and (existing_instance is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_instance:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_instance:
            if differences_detected:
                instance_id_to_update = existing_instance.get("instance_id")
                if not instance_id_to_update:
                    module.fail_json(
                        msg="Cannot update cloud app instance: ID is missing from the existing resource."
                    )

                updated_instance, _unused, error = (
                    client.cloud_app_instances.update_cloud_app_instances(
                        instance_id=instance_id_to_update,
                        instance_name=instance_params.get("instance_name"),
                        instance_type=instance_params.get("instance_type"),
                        instance_identifiers=instance_params.get(
                            "instance_identifiers"
                        ),
                    )
                )
                if error:
                    module.fail_json(msg=f"Error updating label: {to_native(error)}")
                module.exit_json(changed=True, data=updated_instance.as_dict())
            else:
                module.exit_json(changed=False, data=existing_instance)
        else:
            new_instance, _unused, error = (
                client.cloud_app_instances.add_cloud_app_instances(
                    instance_name=instance_params.get("instance_name"),
                    instance_type=instance_params.get("instance_type"),
                    instance_identifiers=instance_params.get("instance_identifiers"),
                )
            )
            if error:
                module.fail_json(
                    msg=f"Error adding cloud app instance: {to_native(error)}"
                )
            module.exit_json(changed=True, data=new_instance.as_dict())

    elif state == "absent":
        if existing_instance:
            instance_id_to_delete = existing_instance.get("instance_id")
            if not instance_id_to_delete:
                module.fail_json(
                    msg="Cannot delete cloud app instance: ID is missing from the existing resource."
                )

            _unused, _unused, error = (
                client.cloud_app_instances.delete_cloud_app_instances(
                    instance_id_to_delete
                )
            )
            if error:
                module.fail_json(
                    msg=f"Error deleting cloud app instance: {to_native(error)}"
                )
            module.exit_json(changed=True, data=existing_instance)
        else:
            module.exit_json(changed=False, data={})

    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            instance_id=dict(type="int", required=False),
            instance_name=dict(type="str", required=True),
            instance_type=dict(
                type="str",
                required=True,
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
            instance_identifiers=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    instance_identifier_name=dict(type="str", required=True),
                    instance_identifier=dict(type="str", required=True),
                    identifier_type=dict(
                        type="str",
                        required=True,
                        choices=["URL", "REFURL", "KEYWORD"],
                    ),
                ),
            ),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
