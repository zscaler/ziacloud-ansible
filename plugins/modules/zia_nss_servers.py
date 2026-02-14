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
module: zia_nss_servers
short_description: "Adds a new NSS server."
description:
  - "Adds a new NSS server."
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
  id:
    description: "The unique identifier for the nss server"
    type: int
  name:
    description: "NSS server name"
    required: true
    type: str
  status:
    description:
      - The health of the NSS server
    required: false
    type: str
    choices:
        - ENABLED
        - DISABLED
  type:
    description:
      - The type of the NSS server
    required: false
    type: str
    choices:
        - NSS_FOR_WEB
        - NSS_FOR_FIREWALL
"""

EXAMPLES = r"""

- name: Create/Update/Delete nss server.
  zscaler.ziacloud.zia_nss_servers:
    provider: '{{ provider }}'
    name: "Example"
    status: "ENABLED"
    type: "NSS_FOR_FIREWALL"
"""

RETURN = r"""
# The newly created nss server resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_nss_server(nss_server):
    """
    Remove computed attributes from a nss server dict to make comparison easier.
    """
    normalized = nss_server.copy() if nss_server else {}
    computed_values = ["id"]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    rule_nss_params = {p: module.params.get(p) for p in ["id", "name", "status", "type"]}
    nss_id = rule_nss_params.get("id")
    nss_name = rule_nss_params.get("name")

    existing_nss_server = None

    if nss_id:
        result, _unused, error = client.nss_servers.get_nss_server(nss_id)
        if error:
            module.fail_json(msg=f"Error fetching nss server with id {nss_id}: {to_native(error)}")
        existing_nss_server = result.as_dict()
    else:
        result, _unused, error = client.nss_servers.list_nss_servers()
        if error:
            module.fail_json(msg=f"Error listing nss servers: {to_native(error)}")
        nss_servers_list = [nss.as_dict() for nss in result]
        if nss_name:
            for nss in nss_servers_list:
                if nss.get("name") == nss_name:
                    existing_nss_server = nss
                    break

    normalized_desired = normalize_nss_server(rule_nss_params)
    normalized_existing = normalize_nss_server(existing_nss_server) if existing_nss_server else {}

    differences_detected = False
    for key, value in normalized_desired.items():
        if normalized_existing.get(key) != value:
            differences_detected = True
            module.warn(f"Difference detected in {key}. Current: {normalized_existing.get(key)}, Desired: {value}")

    if module.check_mode:
        if state == "present" and (existing_nss_server is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_nss_server:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_nss_server:
            if differences_detected:
                nss_id_to_update = existing_nss_server.get("id")
                if not nss_id_to_update:
                    module.fail_json(msg="Cannot update nss server: ID is missing from the existing resource.")

                updated_nss_server, _unused, error = client.nss_servers.update_nss_server(
                    nss_id=nss_id_to_update,
                    name=rule_nss_params.get("name"),
                    status=rule_nss_params.get("status"),
                    type=rule_nss_params.get("type"),
                )
                if error:
                    module.fail_json(msg=f"Error updating nss server: {to_native(error)}")
                module.exit_json(changed=True, data=updated_nss_server.as_dict())
            else:
                module.exit_json(changed=False, data=existing_nss_server)
        else:
            new_nss_server, _unused, error = client.nss_servers.add_nss_server(
                name=rule_nss_params.get("name"),
                status=rule_nss_params.get("status"),
                type=rule_nss_params.get("type"),
            )
            if error:
                module.fail_json(msg=f"Error adding nss server: {to_native(error)}")
            module.exit_json(changed=True, data=new_nss_server.as_dict())

    elif state == "absent":
        if existing_nss_server:
            nss_id_to_delete = existing_nss_server.get("id")
            if not nss_id_to_delete:
                module.fail_json(msg="Cannot delete nss server: ID is missing from the existing resource.")

            _unused, _unused, error = client.nss_servers.delete_nss_server(nss_id_to_delete)
            if error:
                module.fail_json(msg=f"Error deleting nss server: {to_native(error)}")
            module.exit_json(changed=True, data=existing_nss_server)
        else:
            module.exit_json(changed=False, data={})

    else:
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        dict(
            id=dict(type="int", required=False),
            name=dict(type="str", required=True),
            status=dict(
                type="str",
                required=False,
                choices=[
                    "ENABLED",
                    "DISABLED",
                ],
            ),
            type=dict(
                type="str",
                required=False,
                choices=[
                    "NSS_FOR_WEB",
                    "NSS_FOR_FIREWALL",
                ],
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
