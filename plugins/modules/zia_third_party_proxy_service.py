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
module: zia_third_party_proxy_service
short_description: "Adds a new object for a third-party proxy service"
description:
  - "Adds a new object for a third-party proxy service"
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
    description: "The unique identifier for the proxy"
    type: int
  name:
    description: "The name of the Proxy"
    required: true
    type: str
  description:
    description:
      - Additional notes or information
    required: false
    type: str
  type:
    description:
      - Gateway type
    required: false
    type: str
    choices:
        - PROXYCHAIN
        - ZIA
        - ECSELF
  address:
    description:
      - The IP address or the FQDN of the third-party proxy service
    required: false
    type: str
  port:
    description:
      - The port number on which the third-party proxy service listens to the requests forwarded from Zscaler
    required: false
    type: int
  insert_xau_header:
    description:
      - Flag indicating whether X-Authenticated-User header is added by the proxy.
    required: false
    type: bool
  base64_encode_xau_header:
    description:
      - Flag indicating whether the added X-Authenticated-User header is Base64 encoded.
    required: false
    type: bool
  cert:
    description: The root certificate used by the third-party proxy to perform SSL inspection.
    required: false
    type: dict
    suboptions:
      id:
        description: A unique identifier for an entity
        required: false
        type: int
"""

EXAMPLES = r"""

- name: Create/Update/Delete proxy.
  zscaler.ziacloud.zia_third_party_proxy_service:
    name: Proxy01Ansible
    description: Proxy01Ansible
    type: PROXYCHAIN
    address: "192.168.1.1"
    port: 5000
    insert_xau_header: true
    base64_encode_xau_header: true
"""

RETURN = r"""
# The newly created proxies resource record.
"""

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def normalize_proxies(proxy):
    """
    Remove computed attributes from a proxies dict to make comparison easier.
    """
    normalized = proxy.copy() if proxy else {}
    computed_values = ["id"]
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def core(module):
    state = module.params.get("state")
    client = ZIAClientHelper(module)

    proxy_params = {
        p: module.params.get(p)
        for p in [
            "id",
            "name",
            "description",
            "type",
            "address",
            "port",
            "insert_xau_header",
            "base64_encode_xau_header",
            "cert",
        ]
    }
    proxy_id = proxy_params.get("id")
    proxy_name = proxy_params.get("name")

    existing_proxy = None

    if proxy_id:
        result, _unused, error = client.proxies.get_proxy(proxy_id)
        if error:
            module.fail_json(
                msg=f"Error fetching proxy with id {proxy_id}: {to_native(error)}"
            )
        existing_proxy = result.as_dict()
    else:
        result, _unused, error = client.proxies.list_proxies()
        if error:
            module.fail_json(msg=f"Error listing proxies: {to_native(error)}")
        proxies_list = [proxy.as_dict() for proxy in result]
        if proxy_name:
            for proxy in proxies_list:
                if proxy.get("name") == proxy_name:
                    existing_proxy = proxy
                    break

    normalized_desired = normalize_proxies(proxy_params)
    normalized_existing = normalize_proxies(existing_proxy) if existing_proxy else {}

    differences_detected = False
    for key, value in normalized_desired.items():
        if normalized_existing.get(key) != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {normalized_existing.get(key)}, Desired: {value}"
            )

    if module.check_mode:
        if state == "present" and (existing_proxy is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_proxy:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    if state == "present":
        if existing_proxy:
            if differences_detected:
                proxy_id_to_update = existing_proxy.get("id")
                if not proxy_id_to_update:
                    module.fail_json(
                        msg="Cannot update proxy: ID is missing from the existing resource."
                    )

                updated_proxy, _unused, error = client.proxies.update_proxy(
                    proxy_id=proxy_id_to_update,
                    name=proxy_params.get("name"),
                    description=proxy_params.get("description"),
                    type=proxy_params.get("type"),
                    address=proxy_params.get("address"),
                    port=proxy_params.get("port"),
                    insert_xau_header=proxy_params.get("insert_xau_header"),
                    base64_encode_xau_header=proxy_params.get(
                        "base64_encode_xau_header"
                    ),
                    cert=proxy_params.get("cert"),
                )
                if error:
                    module.fail_json(msg=f"Error updating proxy: {to_native(error)}")
                module.exit_json(changed=True, data=updated_proxy.as_dict())
            else:
                module.exit_json(changed=False, data=existing_proxy)
        else:
            new_proxy, _unused, error = client.proxies.add_proxy(
                name=proxy_params.get("name"),
                description=proxy_params.get("description"),
                type=proxy_params.get("type"),
                address=proxy_params.get("address"),
                port=proxy_params.get("port"),
                insert_xau_header=proxy_params.get("insert_xau_header"),
                base64_encode_xau_header=proxy_params.get("base64_encode_xau_header"),
                cert=proxy_params.get("cert"),
            )
            if error:
                module.fail_json(msg=f"Error adding proxy: {to_native(error)}")
            module.exit_json(changed=True, data=new_proxy.as_dict())

    elif state == "absent":
        if existing_proxy:
            proxy_id_to_delete = existing_proxy.get("id")
            if not proxy_id_to_delete:
                module.fail_json(
                    msg="Cannot delete proxy: ID is missing from the existing resource."
                )

            _unused, _unused, error = client.proxies.delete_proxy(proxy_id_to_delete)
            if error:
                module.fail_json(msg=f"Error deleting proxy: {to_native(error)}")
            module.exit_json(changed=True, data=existing_proxy)
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
            description=dict(type="str", required=False),
            type=dict(
                type="str", required=False, choices=["PROXYCHAIN", "ZIA", "ECSELF"]
            ),
            address=dict(type="str", required=False),
            port=dict(type="int", required=False),
            insert_xau_header=dict(type="bool", required=False),
            base64_encode_xau_header=dict(type="bool", required=False),
            cert=dict(
                type="dict",
                required=False,
                options=dict(
                    id=dict(type="int", required=False),
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
