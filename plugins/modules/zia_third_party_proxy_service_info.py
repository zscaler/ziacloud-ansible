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
module: zia_third_party_proxy_service_info
short_description: "Retrieves a list of all proxies configured for third-party proxy services"
description:
  - "Retrieves a list of all proxies configured for third-party proxy services"
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
  id:
    description: "The unique identifier for the 3rd-party proxy"
    type: int
    required: false
  name:
    description: "The 3rd-party proxy name."
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gets all list of 3rd-party proxy
  zscaler.ziacloud.zia_third_party_proxy_service_info:
    provider: '{{ provider }}'

- name: Gets a list of 3rd-party proxy by name
  zscaler.ziacloud.zia_third_party_proxy_service_info:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
proxies:
  description: A list of third-party proxies fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier for the third-party proxy.
      type: int
      returned: always
      sample: 18206641
    name:
      description: The name of the third-party proxy.
      type: str
      returned: always
      sample: "Proxy01"
    description:
      description: A description of the third-party proxy.
      type: str
      returned: always
      sample: "Proxy01test"
    address:
      description: The IP address or the FQDN of the third-party proxy service
      type: str
      returned: always
      sample: "192.168.100.1"
    port:
      description: The port number on which the third-party proxy service listens to the requests forwarded from Zscaler
      type: int
      returned: always
      sample: 5000
    type:
      description: The proxy type.
      type: str
      returned: always
      sample: "PROXYCHAIN"
    insert_xau_header:
      description: Flag indicating whether X-Authenticated-User header is added by the proxy.
      type: bool
      returned: always
      sample: true
    base64_encode_xau_header:
      description: Flag indicating whether the added X-Authenticated-User header is Base64 encoded.
      type: bool
      returned: always
      sample: true
    last_modified_time:
      description: Timestamp of when the proxy was last modified
      type: int
      returned: always
      sample: 1745861609
    last_modified_by:
      description: Last user that modified the proxy
      type: dict
      returned: always
      contains:
        id:
          description: ID of the user who modified the proxy.
          type: int
          sample: 19474996
        name:
          description: Name of the user who modified the proxy.
          type: str
          sample: "admin@acme.zsloginbeta.net"
        external_id:
          description: Whether the user has an external identity.
          type: bool
          sample: false
        extensions:
          description: Extension metadata of the user.
          type: dict
          sample: {"id": 19474996, "name": "admin@acme.zsloginbeta.net"}
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    proxy_id = module.params.get("id")
    proxy_name = module.params.get("name")

    client = ZIAClientHelper(module)
    proxies = []

    if proxy_id is not None:
        proxy_obj, _unused, error = client.proxies.get_proxy(proxy_id)
        if error or proxy_obj is None:
            module.fail_json(
                msg=f"Failed to retrieve third-party proxy with ID '{proxy_id}': {to_native(error)}"
            )
        proxies = [proxy_obj.as_dict()]
    else:
        query_params = {}
        if proxy_name:
            query_params["search"] = proxy_name

        result, _unused, error = client.proxies.list_proxies(query_params=query_params)
        if error:
            module.fail_json(
                msg=f"Error retrieving third-party proxys: {to_native(error)}"
            )

        proxy_list = [g.as_dict() for g in result] if result else []

        if proxy_name:
            matched = next((g for g in proxy_list if g.get("name") == proxy_name), None)
            if not matched:
                available = [g.get("name") for g in proxy_list]
                module.fail_json(
                    msg=f"third-party proxy with name '{proxy_name}' not found. Available proxies: {available}"
                )
            proxies = [matched]
        else:
            proxies = proxy_list

    module.exit_json(changed=False, proxies=proxies)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["name", "id"]],
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
