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
module: zia_cloud_firewall_network_services_info
short_description: "Gets a list of all network services."
description:
  - "Gets a list of all network services."
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
  id:
    description: "The unique identifier for the network services"
    required: false
    type: int
  name:
    description: "The network services name"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all Network Services
  zscaler.ziacloud.zia_cloud_firewall_network_services_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a Network Services by Name
  zscaler.ziacloud.zia_cloud_firewall_network_services_info:
    provider: '{{ provider }}'
    name: "ICMP_ANY"
"""

RETURN = r"""
services:
  description: Details about the network services retrieved.
  returned: when successful
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier of the network service.
      returned: always
      type: int
      sample: 1300953
    name:
      description: The name of the network service.
      returned: always
      type: str
      sample: "ICMP_ANY"
    description:
      description: Description of the network service.
      returned: always
      type: str
      sample: "ICMP_ANY_DESC"
    tag:
      description: The tag assigned to the network service.
      returned: always
      type: str
      sample: "ICMP_ANY"
    type:
      description: The type of network service (e.g., STANDARD or CUSTOM).
      returned: always
      type: str
      sample: "STANDARD"
    creator_context:
      description: The context in which the network service was created (e.g., ZIA, user).
      returned: always
      type: str
      sample: "ZIA"
    is_name_l10n_tag:
      description: Indicates if the name of the service is a localization tag.
      returned: always
      type: bool
      sample: true
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    service_id = module.params.get("id")
    service_name = module.params.get("name")

    client = ZIAClientHelper(module)
    services = []

    if service_id is not None:
        service_obj, _unused, error = client.cloud_firewall.get_network_service(service_id)
        if error or service_obj is None:
            module.fail_json(msg=f"Failed to retrieve Network Services with ID '{service_id}': {to_native(error)}")
        services = [service_obj.as_dict()]
    else:
        query_params = {}
        if service_name:
            query_params["search"] = service_name

        result, _unused, error = client.cloud_firewall.list_network_services(query_params=query_params)
        if error:
            module.fail_json(msg=f"Error retrieving Network Services: {to_native(error)}")

        service_list = [g.as_dict() for g in result] if result else []

        if service_name:
            matched = next((g for g in service_list if g.get("name") == service_name), None)
            if not matched:
                available = [g.get("name") for g in service_list]
                module.fail_json(msg=f"Network Services with name '{service_name}' not found. Available services: {available}")
            services = [matched]
        else:
            services = service_list

    module.exit_json(changed=False, services=services)


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
